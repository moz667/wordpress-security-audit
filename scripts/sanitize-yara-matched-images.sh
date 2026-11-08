#!/bin/sh

WWWROOT="${WWWROOT:-/var/www/html}"
QUARANTINE_ROOT="${QUARANTINE_ROOT:-/var/www/quarantine}"
YARA_RULES="${YARA_RULES:-/usr/share/yara-rules/php.yar}"
WHITELIST_HELPER="${WHITELIST_HELPER:-/usr/local/bin/wsa-add-file-to-whitelist.sh}"

if [ ! -d "$WWWROOT" ]; then
    echo "Error: WordPress root not found: $WWWROOT" >&2
    exit 1
fi

wwwroot=$(realpath "$WWWROOT") || {
    echo "Error: could not resolve WordPress root: $WWWROOT" >&2
    exit 1
}

if [ ! -x "$WHITELIST_HELPER" ]; then
    echo "Error: whitelist helper is not executable: $WHITELIST_HELPER" >&2
    exit 1
fi

mkdir -p "$QUARANTINE_ROOT" || {
    echo "Error: could not create quarantine directory: $QUARANTINE_ROOT" >&2
    exit 1
}

matches=$(mktemp) || exit 1
sanitized=$(mktemp) || {
    rm -f "$matches"
    exit 1
}
sorted_matches="$matches.sorted"
trap 'rm -f "$matches" "$sanitized" "$sorted_matches"' EXIT HUP INT TERM

if ! yara -r "$YARA_RULES" "$wwwroot" > "$matches"; then
    echo "Error: YARA scan failed for $wwwroot" >&2
    exit 1
fi

awk '
    {
        sub(/^[^[:space:]]+[[:space:]]+/, "")
        if (length($0))
            print
    }
' "$matches" | sort -u > "$sorted_matches" || {
    echo "Error: could not prepare the list of YARA matches" >&2
    exit 1
}
mv "$sorted_matches" "$matches" || exit 1

status=0
while IFS= read -r image || [ -n "$image" ]; do
    [ -n "$image" ] || continue
    [ -f "$image" ] || continue

    image_path=$(realpath "$image") || {
        echo "Error: could not resolve matched file: $image" >&2
        status=1
        continue
    }
    case "$image_path" in
        "$wwwroot"/*) relpath=${image_path#"$wwwroot"/} ;;
        *)
            echo "Error: matched file is outside $wwwroot: $image" >&2
            status=1
            continue
            ;;
    esac

    if ! identify "$image_path" >/dev/null 2>&1; then
        continue
    fi

    image_dir=$(dirname "$image_path")
    image_name=$(basename "$image_path")
    image_extension=${image_name##*.}
    if [ "$image_extension" = "$image_name" ]; then
        image_extension=img
    fi
    temp_dir=$(mktemp -d "$image_dir/.sanitize.XXXXXX") || {
        echo "Error: could not create temporary directory for $relpath" >&2
        status=1
        continue
    }
    temp_first="$temp_dir/image.$image_extension"
    temp_final="$temp_dir/sanitized.$image_extension"
    if ! magick "$image_path" -flip -strip "$temp_first" ||
        ! magick "$temp_first" -flip "$temp_final"; then
        echo "Error: could not sanitize $relpath" >&2
        rm -rf "$temp_dir"
        status=1
        continue
    fi

    timestamp=$(date '+%Y%m%dT%H%M%S.%6N') || {
        echo "Error: could not determine the current timestamp" >&2
        rm -rf "$temp_dir"
        status=1
        continue
    }
    quarantine_path="$QUARANTINE_ROOT/$relpath"
    backup_dir=$(dirname "$quarantine_path")
    if ! mkdir -p "$backup_dir"; then
        echo "Error: could not create quarantine directory for $relpath" >&2
        rm -rf "$temp_dir"
        status=1
        continue
    fi
    if [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; then
        backup_base="$quarantine_path.original.$timestamp.$$"
        quarantine_path="$backup_base"
        backup_number=0
        while [ -e "$quarantine_path" ] || [ -L "$quarantine_path" ]; do
            backup_number=$((backup_number + 1))
            quarantine_path="$backup_base.$backup_number"
        done
    fi
    if ! cp -p "$image_path" "$quarantine_path"; then
        echo "Error: could not back up $relpath to quarantine" >&2
        rm -rf "$temp_dir"
        status=1
        continue
    fi
    if ! chmod --reference="$image_path" "$temp_final" ||
        ! mv "$temp_final" "$image_path"; then
        echo "Error: could not replace $relpath with its sanitized copy" >&2
        rm -rf "$temp_dir"
        status=1
        continue
    fi
    rm -rf "$temp_dir"
    printf '%s\n' "$image_path" >> "$sanitized" || {
        echo "Error: could not record sanitized file $relpath" >&2
        status=1
        continue
    }
    echo "Sanitized: $relpath (original saved to $quarantine_path)" >&2
done < "$matches"

if [ -s "$sanitized" ]; then
    if ! "$WHITELIST_HELPER" --files-from "$sanitized"; then
        echo "Error: could not add sanitized image hashes to the custom whitelist" >&2
        status=1
    fi
fi

exit "$status"
