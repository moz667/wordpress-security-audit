#!/bin/sh

WWWROOT="${WWWROOT:-/var/www/html}"
QUARANTINE_ROOT="${QUARANTINE_ROOT:-/var/www/quarantine}"
YARA_RULES="${YARA_RULES:-/usr/share/yara-rules/php.yar}"
WHITELIST_HELPER="${WHITELIST_HELPER:-/usr/local/bin/wsa-add-file-to-whitelist.sh}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [-h|--help]

Interactively review files matched by YARA.
For each matching file, show matching strings and offsets with YARA -s, then:
  c  Continue to the next file
  a  Add the file to the custom whitelist
  m  Move the file to quarantine
  q  Quit

Configuration is available through WWWROOT, YARA_RULES, QUARANTINE_ROOT,
and WHITELIST_HELPER environment variables.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
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
done

if [ ! -d "$WWWROOT" ]; then
    echo "Error: WordPress root not found: $WWWROOT" >&2
    exit 1
fi

wwwroot=$(realpath "$WWWROOT") || {
    echo "Error: could not resolve WordPress root: $WWWROOT" >&2
    exit 1
}

if [ ! -r "$YARA_RULES" ]; then
    echo "Error: YARA rules not found or not readable: $YARA_RULES" >&2
    exit 1
fi

if ! command -v yara >/dev/null 2>&1; then
    echo "Error: yara is not installed or not on PATH" >&2
    exit 1
fi

matches=$(mktemp) || {
    echo "Error: could not create a temporary file for YARA matches" >&2
    exit 1
}
raw_files=$(mktemp) || {
    rm -f "$matches"
    echo "Error: could not create a temporary file for matched files" >&2
    exit 1
}
files=$(mktemp) || {
    rm -f "$matches" "$raw_files"
    echo "Error: could not create a temporary file for matched files" >&2
    exit 1
}
detailed_matches=$(mktemp) || {
    rm -f "$matches" "$raw_files" "$files"
    echo "Error: could not create a temporary file for detailed YARA matches" >&2
    exit 1
}
trap 'rm -f "$matches" "$raw_files" "$files" "$detailed_matches"' EXIT HUP INT TERM

yara -r "$YARA_RULES" "$wwwroot" > "$matches"
yara_status=$?
if [ "$yara_status" -eq 1 ]; then
    echo "No YARA matches found in $wwwroot."
    exit 0
elif [ "$yara_status" -ne 0 ]; then
    echo "Error: YARA scan failed for $wwwroot (exit status $yara_status)" >&2
    exit "$yara_status"
fi

if ! awk '
    {
        sub(/^[^[:space:]]+[[:space:]]/, "")
        if (length($0))
            print
    }
' "$matches" > "$raw_files"; then
    echo "Error: could not extract matched file paths" >&2
    exit 1
fi

if ! sort -u "$raw_files" > "$files"; then
    echo "Error: could not sort matched file paths" >&2
    exit 1
fi

status=0
while IFS= read -r file <&3 || [ -n "$file" ]; do
    [ -n "$file" ] || continue
    if [ ! -f "$file" ]; then
        echo "Error: matched file is no longer a regular file: $file" >&2
        status=1
        continue
    fi

    file_path=$(realpath "$file") || {
        echo "Error: could not resolve matched file: $file" >&2
        status=1
        continue
    }
    case "$file_path" in
        "$wwwroot"/*) relpath=${file_path#"$wwwroot"/} ;;
        *)
            echo "Error: matched file is outside $wwwroot: $file" >&2
            status=1
            continue
            ;;
    esac

    printf '\n=== %s ===\n' "$relpath"
    yara -s "$YARA_RULES" "$file_path" > "$detailed_matches"
    yara_status=$?
    if [ "$yara_status" -eq 1 ]; then
        echo "The file no longer matches YARA; skipping it." >&2
        continue
    elif [ "$yara_status" -ne 0 ]; then
        echo "Error: detailed YARA scan failed for $file_path (exit status $yara_status)" >&2
        status=1
        continue
    fi
    if ! awk '
        /^[[:space:]]*0x[[:xdigit:]]+:/ {
            print ""
        }
        { print }
    ' "$detailed_matches"; then
        echo "Error: could not format detailed YARA matches for $file_path" >&2
        status=1
        continue
    fi

    while :; do
        printf '\nAction [c]ontinue, [a]dd to whitelist, [m]ove to quarantine, [q]uit: '
        if ! IFS= read -r choice; then
            echo >&2
            echo "Error: could not read an action from standard input" >&2
            exit 1
        fi

        case "$choice" in
            c|C)
                break
                ;;
            a|A)
                if [ ! -x "$WHITELIST_HELPER" ]; then
                    echo "Error: whitelist helper is not executable: $WHITELIST_HELPER" >&2
                    status=1
                elif "$WHITELIST_HELPER" "$file_path"; then
                    echo "Added to whitelist: $relpath"
                else
                    echo "Error: could not add $relpath to the whitelist" >&2
                    status=1
                fi
                break
                ;;
            m|M)
                if ! mkdir -p "$QUARANTINE_ROOT"; then
                    echo "Error: could not create quarantine directory: $QUARANTINE_ROOT" >&2
                    status=1
                    break
                fi
                quarantine_root=$(realpath "$QUARANTINE_ROOT") || {
                    echo "Error: could not resolve quarantine directory: $QUARANTINE_ROOT" >&2
                    status=1
                    break
                }
                case "$quarantine_root" in
                    "$wwwroot"|"$wwwroot"/*)
                        echo "Error: quarantine directory must be outside the WordPress root: $quarantine_root" >&2
                        status=1
                        break
                        ;;
                esac

                quarantine_path="$quarantine_root/$relpath"
                quarantine_dir=$(dirname "$quarantine_path")
                if ! mkdir -p "$quarantine_dir"; then
                    echo "Error: could not create quarantine directory for $relpath" >&2
                    status=1
                    break
                fi
                quarantine_dir=$(realpath "$quarantine_dir") || {
                    echo "Error: could not resolve quarantine directory for $relpath" >&2
                    status=1
                    break
                }
                case "$quarantine_dir" in
                    "$quarantine_root"|"$quarantine_root"/*) ;;
                    *)
                        echo "Error: quarantine path escapes the quarantine directory: $relpath" >&2
                        status=1
                        break
                        ;;
                esac
                quarantine_path="$quarantine_dir/$(basename "$file_path")"
                if [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
                    timestamp=$(date '+%Y%m%dT%H%M%S') || {
                        echo "Error: could not determine the current timestamp" >&2
                        status=1
                        break
                    }
                    quarantine_base="$quarantine_path.original.$timestamp.$$"
                    quarantine_path="$quarantine_base"
                    suffix=0
                    while [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; do
                        suffix=$((suffix + 1))
                        quarantine_path="$quarantine_base.$suffix"
                    done
                fi
                if ! mv -n "$file_path" "$quarantine_path" ||
                    [ -e "$file_path" ] || [ -L "$file_path" ]; then
                    echo "Error: could not move $relpath to quarantine" >&2
                    status=1
                else
                    echo "Moved to quarantine: $quarantine_path"
                fi
                break
                ;;
            q|Q)
                exit "$status"
                ;;
            *)
                echo "Choose c, a, m, or q."
                ;;
        esac
    done
done 3< "$files"

exit "$status"
