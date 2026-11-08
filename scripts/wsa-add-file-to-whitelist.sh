#!/bin/sh
#
# Adds the sha256 hash of the given file(s) to the custom YARA whitelist,
# just before the "// End rule" marker:
#
#   hash.sha256(0, filesize) == "<sha256>" or // <path relative to $WWWROOT>
#
# Usage: wsa-add-file-to-whitelist.sh <file> [<file> ...]

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
    echo "Usage: $(basename "$0") <file> [<file> ...] | --files-from <list>" >&2
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
files=$(mktemp) || exit 1
rules=$(mktemp) || exit 1
temporary=$(mktemp "$(dirname "$CUSTOM_WHITELIST")/.whitelist.XXXXXX") || {
    rm -f "$files" "$rules"
    exit 1
}
trap 'rm -f "$files" "$rules" "$temporary"' EXIT HUP INT TERM

if [ "$1" = "--files-from" ]; then
    if [ "$#" -ne 2 ] || [ ! -r "$2" ] || ! cat < "$2" > "$files"; then
        echo "Error: expected a readable list after --files-from" >&2
        exit 1
    fi
else
    for file in "$@"; do
        printf '%s\n' "$file" >> "$files" || {
            echo "Error: could not stage file list" >&2
            exit 1
        }
    done
fi

while IFS= read -r file || [ -n "$file" ]; do
    [ -n "$file" ] || continue
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

    if grep -qF "\"$hash\"" "$rules"; then
        continue
    fi

    printf '%s\n' "${INDENT}hash.sha256(0, filesize) == \"$hash\" or  // $relpath" >> "$rules" || {
        echo "Error: could not stage hash for $relpath" >&2
        status=1
        continue
    }
    echo "Added: $relpath ($hash)" >&2
done < "$files"

if [ -s "$rules" ]; then
    timestamp=$(date '+%Y-%m-%dT%H:%M:%S.%6N') || {
        echo "Error: could not determine the current timestamp" >&2
        exit 1
    }
    if ! RULES_FILE="$rules" MARKER="$END_MARKER" TIMESTAMP="$timestamp" awk '
        /^[[:space:]]*last_updated[[:space:]]*=/ {
            timestamp_count++
            sub(/"[^"]*"/, "\"" ENVIRON["TIMESTAMP"] "\"")
        }
        !done && index($0, ENVIRON["MARKER"]) {
            while ((getline rule < ENVIRON["RULES_FILE"]) > 0)
                print rule
            close(ENVIRON["RULES_FILE"])
            done = 1
        }
        { print }
        END {
            if (timestamp_count != 1 || !done)
                exit 1
        }
    ' "$CUSTOM_WHITELIST" > "$temporary"; then
        echo "Error: could not stage hash or last_updated in $CUSTOM_WHITELIST" >&2
        exit 1
    fi
    if ! chmod "$(stat -c '%a' "$CUSTOM_WHITELIST")" "$temporary" ||
        ! mv "$temporary" "$CUSTOM_WHITELIST"; then
        echo "Error: could not update $CUSTOM_WHITELIST" >&2
        exit 1
    fi
fi

exit $status
