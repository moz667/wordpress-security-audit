#!/bin/sh

WWWROOT="${WWWROOT:-/var/www/html}"
YARA_RULES="${YARA_RULES:-/usr/share/yara-rules/php.yar}"
AUTO_WHITELIST_SCRIPT="${AUTO_WHITELIST_SCRIPT:-/usr/local/bin/wsa-auto-add-to-whitelists.sh}"
SANITIZE_IMAGES_SCRIPT="${SANITIZE_IMAGES_SCRIPT:-/usr/local/bin/wsa-sanitize-images.sh}"

AUTO_ADD=0
SANITIZE_IMAGES=0
VERBOSE=0
SCAN_FILE=""
SCAN_FILE_SET=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTION]
       $(basename "$0") --file PATH [--verbose]

Run the YARA scan, optionally preparing whitelists first:
  -a, --auto-add-to-whitelist  Generate official and third-party whitelist rules
  -i, --sanitize-images        Sanitize YARA-matched images
  -A, --all                    Run both preparation steps before scanning
  --file PATH                  Scan one file under the WordPress root; skips preparation
  -v, --verbose                Verbose output
  -h, --help                   Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -a|--auto-add-to-whitelist)
            AUTO_ADD=1
            ;;
        -i|--sanitize-images)
            SANITIZE_IMAGES=1
            ;;
        -A|--all)
            AUTO_ADD=1
            SANITIZE_IMAGES=1
            ;;
        --file)
            if [ "$SCAN_FILE_SET" -eq 1 ] || [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "Error: --file requires exactly one file path" >&2
                usage >&2
                exit 2
            fi
            SCAN_FILE="$2"
            SCAN_FILE_SET=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

SCAN_TARGET="$WWWROOT"
if [ "$SCAN_FILE_SET" -eq 1 ]; then
    if [ "$AUTO_ADD" -eq 1 ] || [ "$SANITIZE_IMAGES" -eq 1 ]; then
        echo "Error: --file cannot be combined with whitelist generation or image sanitization" >&2
        exit 2
    fi

    case "$SCAN_FILE" in
        /*) requested_file="$SCAN_FILE" ;;
        *) requested_file="$WWWROOT/$SCAN_FILE" ;;
    esac

    if [ ! -f "$requested_file" ]; then
        echo "Error: file not found or not a regular file: $SCAN_FILE" >&2
        exit 2
    fi

    scan_root=$(realpath "$WWWROOT") || {
        echo "Error: WordPress root not found: $WWWROOT" >&2
        exit 2
    }
    SCAN_TARGET=$(realpath "$requested_file") || {
        echo "Error: unable to resolve file path: $SCAN_FILE" >&2
        exit 2
    }
    case "$SCAN_TARGET" in
        "$scan_root"/*) ;;
        *)
            echo "Error: file must be inside the WordPress root: $WWWROOT" >&2
            exit 2
            ;;
    esac
fi

run_pre_scan_step() {
    step_name=$1
    step_script=$2

    if [ ! -x "$step_script" ]; then
        echo "Error: $step_name script not found or not executable: $step_script" >&2
        return 127
    fi

    echo "- Running $step_name..." >&2
    if "$step_script"; then
        return 0
    else
        step_status=$?
        echo "Error: $step_name failed with exit status $step_status; scan aborted" >&2
        return "$step_status"
    fi
}

if [ "$AUTO_ADD" -eq 1 ]; then
    run_pre_scan_step "automatic whitelist generation" "$AUTO_WHITELIST_SCRIPT" || exit $?
fi

if [ "$SANITIZE_IMAGES" -eq 1 ]; then
    run_pre_scan_step "image sanitization" "$SANITIZE_IMAGES_SCRIPT" || exit $?
fi

echo "- Running scan..." >&2
SCAN_OUTPUT=$(mktemp) || {
    echo "Error: unable to create temporary file for scan output" >&2
    exit 1
}
trap 'rm -f "$SCAN_OUTPUT"' EXIT HUP INT TERM

if [ "$VERBOSE" -eq 1 ]; then
    if [ "$SCAN_FILE_SET" -eq 1 ]; then
        yara -s "$YARA_RULES" "$SCAN_TARGET" > "$SCAN_OUTPUT"
    else
        yara -s -r "$YARA_RULES" "$SCAN_TARGET" > "$SCAN_OUTPUT"
    fi
else
    if [ "$SCAN_FILE_SET" -eq 1 ]; then
        yara "$YARA_RULES" "$SCAN_TARGET" > "$SCAN_OUTPUT"
    else
        yara -r "$YARA_RULES" "$SCAN_TARGET" > "$SCAN_OUTPUT"
    fi
fi
scan_status=$?
cat "$SCAN_OUTPUT"
if [ "$scan_status" -ne 0 ]; then
    exit "$scan_status"
fi
if [ -s "$SCAN_OUTPUT" ]; then
    exit 0
fi
if [ "$SCAN_FILE_SET" -eq 1 ]; then
    echo "No malware matches found in $SCAN_TARGET."
else
    echo "Congrats! The coast is clear (no malware matches found)."
fi
