#!/bin/sh

WWWROOT="${WWWROOT:-/var/www/html}"
YARA_RULES="${YARA_RULES:-/usr/share/yara-rules/php.yar}"
WHITELIST_HELPER="${WHITELIST_HELPER:-/usr/local/bin/wsa-add-file-to-whitelist.sh}"
PHP_BIN="${PHP_BIN:-php84}"

if [ "$#" -ne 1 ]; then
    echo "Usage: $(basename "$0") <php-file>" >&2
    exit 2
fi

if [ ! -d "$WWWROOT" ]; then
    echo "Error: WordPress root not found: $WWWROOT" >&2
    exit 1
fi

wwwroot=$(realpath "$WWWROOT") || {
    echo "Error: could not resolve WordPress root: $WWWROOT" >&2
    exit 1
}

if [ ! -f "$1" ]; then
    echo "Error: not a regular file: $1" >&2
    exit 1
fi

file_path=$(realpath "$1") || {
    echo "Error: could not resolve file: $1" >&2
    exit 1
}
case "$file_path" in
    "$wwwroot"/*) relpath=${file_path#"$wwwroot"/} ;;
    *)
        echo "Error: file is outside $wwwroot: $1" >&2
        exit 1
        ;;
esac

if [ ! -r "$YARA_RULES" ]; then
    echo "Error: YARA rules not found or not readable: $YARA_RULES" >&2
    exit 1
fi

if ! command -v yara >/dev/null 2>&1; then
    echo "Error: yara is not installed or not on PATH" >&2
    exit 1
fi

if ! command -v "$PHP_BIN" >/dev/null 2>&1; then
    echo "Error: PHP tokenizer is not available; install php84 and php84-tokenizer or set PHP_BIN" >&2
    exit 1
fi

if [ ! -x "$WHITELIST_HELPER" ]; then
    echo "Error: whitelist helper is not executable: $WHITELIST_HELPER" >&2
    exit 1
fi

temporary=$(mktemp) || {
    echo "Error: could not create a temporary file for comment-stripped scan" >&2
    exit 1
}
scan_output=$(mktemp) || {
    rm -f "$temporary"
    echo "Error: could not create a temporary file for YARA output" >&2
    exit 1
}
detailed_output=$(mktemp) || {
    rm -f "$temporary" "$scan_output"
    echo "Error: could not create a temporary file for detailed YARA output" >&2
    exit 1
}
trap 'rm -f "$temporary" "$scan_output" "$detailed_output"' EXIT HUP INT TERM

if ! "$PHP_BIN" -r '
    $source = file_get_contents($argv[1]);
    if ($source === false) {
        fwrite(STDERR, "Error: could not read source file\n");
        exit(1);
    }

    $output = "";
    foreach (token_get_all($source) as $token) {
        if (is_array($token)) {
            $text = $token[1];
            if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                $text = preg_replace("/[^\r\n]/", " ", $text);
                if ($text === null) {
                    fwrite(STDERR, "Error: could not remove PHP comments\n");
                    exit(1);
                }
            }
            $output .= $text;
        } else {
            $output .= $token;
        }
    }

    if (file_put_contents($argv[2], $output) === false) {
        fwrite(STDERR, "Error: could not write comment-stripped source\n");
        exit(1);
    }
' "$file_path" "$temporary"; then
    echo "Error: could not create a comment-stripped copy of $relpath" >&2
    exit 1
fi

yara "$YARA_RULES" "$temporary" > "$scan_output"
yara_status=$?
if [ "$yara_status" -ne 0 ]; then
    echo "Error: YARA scan failed for comment-stripped $relpath (exit status $yara_status)" >&2
    exit "$yara_status"
fi

if [ -s "$scan_output" ]; then
    echo "Still matches YARA after removing PHP comments; not whitelisted: $relpath" >&2
    yara -s "$YARA_RULES" "$temporary" > "$detailed_output"
    yara_status=$?
    if [ "$yara_status" -ne 0 ]; then
        echo "Error: detailed YARA scan failed for comment-stripped $relpath (exit status $yara_status)" >&2
        exit "$yara_status"
    fi
    cat "$detailed_output"
    exit 3
fi

if "$WHITELIST_HELPER" "$file_path"; then
    echo "No YARA matches remain after removing PHP comments; original added to custom whitelist: $relpath"
else
    echo "Error: could not add $relpath to the custom whitelist" >&2
    exit 1
fi
