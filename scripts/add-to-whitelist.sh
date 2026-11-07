#!/bin/sh
#
# Adds the sha256 hash of the given file(s) to the custom YARA whitelist,
# just before the "// End rule" marker:
#
#   hash.sha256(0, filesize) == "<sha256>" or // <path relative to $WWWROOT>
#
# Usage: add-to-whitelist.sh <file> [<file> ...]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WWWROOT="${WWWROOT:-/var/www/html}"
CUSTOM_WHITELIST="${CUSTOM_WHITELIST:-/usr/share/yara-rules/whitelists/99-custom.yar}"

END_MARKER="// End rule"
INDENT="        "

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [ "$#" -eq 0 ]; then
    echo "Usage: $(basename "$0") <file> [<file> ...]" >&2
    exit 1
fi

if [ ! -w "$CUSTOM_WHITELIST" ]; then
    echo "Error: whitelist not found or not writable: $CUSTOM_WHITELIST" >&2
    exit 1
fi

if ! grep -qF "$END_MARKER" "$CUSTOM_WHITELIST"; then
    echo "Error: marker '$END_MARKER' not found in $CUSTOM_WHITELIST" >&2
    exit 1
fi

wwwroot=$(realpath "$WWWROOT")
status=0

for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "Error: not a regular file: $file" >&2
        status=1
        continue
    fi

    path=$(realpath "$file")
    case "$path" in
        "$wwwroot"/*) relpath="${path#"$wwwroot"/}" ;;
        *)
            echo "Error: $file is not inside $wwwroot" >&2
            status=1
            continue
            ;;
    esac

    hash=$(sha256sum "$path" | cut -d ' ' -f 1)

    if grep -qF "\"$hash\"" "$CUSTOM_WHITELIST"; then
        echo "Already whitelisted: $relpath ($hash)" >&2
        continue
    fi

    rule="${INDENT}hash.sha256(0, filesize) == \"$hash\" or  // $relpath"

    tmp=$(mktemp) || exit 1
    RULE="$rule" MARKER="$END_MARKER" awk '
        !done && index($0, ENVIRON["MARKER"]) { print ENVIRON["RULE"]; done = 1 }
        { print }
    ' "$CUSTOM_WHITELIST" > "$tmp" && cat "$tmp" > "$CUSTOM_WHITELIST"
    rm -f "$tmp"

    echo "Added: $relpath ($hash)" >&2
done

exit $status
