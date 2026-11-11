#!/bin/sh

WWWROOT="${WWWROOT:-/var/www/html}"
YARA_RULES="${YARA_RULES:-/usr/share/yara-rules/php.yar}"
OFFICIAL_WHITELIST="${OFFICIAL_WHITELIST:-/usr/share/yara-rules/whitelists/10-oficial-repository.yar}"
THIRD_PARTY_WHITELIST="${THIRD_PARTY_WHITELIST:-/usr/share/yara-rules/whitelists/20-third-party.yar}"
CUSTOM_WHITELIST="${CUSTOM_WHITELIST:-/usr/share/yara-rules/whitelists/99-custom.yar}"
THIRD_PARTY_SCRIPT="${THIRD_PARTY_SCRIPT:-/usr/local/bin/wsa-auto-add-whitelists-third-party.sh}"
CORE_SCRIPT="${CORE_SCRIPT:-/usr/local/bin/wsa-auto-add-whitelists-core.sh}"
PLUGINS_SCRIPT="${PLUGINS_SCRIPT:-/usr/local/bin/wsa-auto-add-whitelists-plugins.sh}"
THEMES_SCRIPT="${THEMES_SCRIPT:-/usr/local/bin/wsa-auto-add-whitelists-themes.sh}"
WHITELIST_ENGINE="${WHITELIST_ENGINE:-/usr/local/bin/lib/wsa-auto-add-whitelists-engine.sh}"
COMMENT_WHITELIST_SCRIPT="${COMMENT_WHITELIST_SCRIPT:-/usr/local/bin/wsa-whitelist-comment-only.sh}"
CUSTOM_WHITELIST_HELPER="${CUSTOM_WHITELIST_HELPER:-/usr/local/bin/wsa-add-file-to-whitelist.sh}"
YARA_OUTPUT_FILTER="${YARA_OUTPUT_FILTER:-/usr/local/bin/wsa-filter-yara-output.php}"
PHP_BIN="${PHP_BIN:-php84}"

DRY_RUN=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [--dry-run]

Generate trusted-source whitelists, then automatically whitelist files
whose YARA findings are limited to printable valid UTF-8 in NonPrintableChars.
EOF
}

for argument in "$@"; do
    case "$argument" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "Error: unknown argument: $argument" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ ! -d "$WWWROOT" ]; then
    echo "Error: WordPress root not found: $WWWROOT" >&2
    exit 1
fi
if [ ! -r "$YARA_RULES" ]; then
    echo "Error: YARA rules not found or not readable: $YARA_RULES" >&2
    exit 1
fi
if ! command -v yara >/dev/null 2>&1; then
    echo "Error: yara is not installed or not on PATH" >&2
    exit 1
fi
if ! command -v "$PHP_BIN" >/dev/null 2>&1; then
    echo "Error: PHP is not installed or not on PATH: $PHP_BIN" >&2
    exit 1
fi

for script in "$THIRD_PARTY_SCRIPT" "$CORE_SCRIPT" "$PLUGINS_SCRIPT" "$THEMES_SCRIPT" \
    "$COMMENT_WHITELIST_SCRIPT" "$CUSTOM_WHITELIST_HELPER"; do
    if [ ! -x "$script" ]; then
        echo "Error: required whitelist helper is not executable: $script" >&2
        exit 1
    fi
done
if [ ! -x "$WHITELIST_ENGINE" ]; then
    echo "Error: whitelist engine is not executable: $WHITELIST_ENGINE" >&2
    exit 1
fi
if [ ! -r "$YARA_OUTPUT_FILTER" ]; then
    echo "Error: UTF-8 classifier not found or not readable: $YARA_OUTPUT_FILTER" >&2
    exit 1
fi

WORK_DIR=$(mktemp -d) || {
    echo "Error: could not create a temporary work directory" >&2
    exit 1
}
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
OFFICIAL_SNAPSHOT="$WORK_DIR/official-whitelist"
THIRD_PARTY_SNAPSHOT="$WORK_DIR/third-party-whitelist"
if ! cp "$OFFICIAL_WHITELIST" "$OFFICIAL_SNAPSHOT" ||
    ! cp "$THIRD_PARTY_WHITELIST" "$THIRD_PARTY_SNAPSHOT"; then
    echo "Error: could not snapshot trusted-source whitelists" >&2
    exit 1
fi

MATCH_OUTPUT="$WORK_DIR/matches"
MATCHED_FILES="$WORK_DIR/matched-files"
ELIGIBLE_FILES="$WORK_DIR/eligible-files"

update_timestamp_if_changed() {
    target=$1
    snapshot=$2
    timestamp=$3

    if cmp -s "$target" "$snapshot"; then
        return 0
    fi

    marker_count=$(awk '/^[[:space:]]*last_updated[[:space:]]*=/ { count++ } END { print count + 0 }' "$target")
    if [ "$marker_count" -ne 1 ]; then
        echo "Error: expected exactly one last_updated field in $target" >&2
        return 1
    fi
    timestamp_file=$(mktemp "$(dirname "$target")/.last-updated.XXXXXX") || return 1
    current_snapshot=$(mktemp) || {
        rm -f "$timestamp_file"
        return 1
    }
    if ! cp -p "$target" "$current_snapshot" ||
        ! awk -v timestamp="$timestamp" '
        /^[[:space:]]*last_updated[[:space:]]*=/ {
            sub(/"[^"]*"/, "\"" timestamp "\"")
            count++
        }
        { print }
        END { if (count != 1) exit 1 }
    ' "$target" > "$timestamp_file" ||
        ! chmod "$(stat -c '%a' "$target")" "$timestamp_file"; then
        rm -f "$timestamp_file" "$current_snapshot"
        echo "Error: could not stage last_updated update for $target" >&2
        return 1
    fi
    if ! cmp -s "$target" "$current_snapshot"; then
        rm -f "$timestamp_file" "$current_snapshot"
        echo "Error: whitelist changed during timestamp update; refusing to overwrite $target" >&2
        return 1
    fi
    if ! mv "$timestamp_file" "$target"; then
        rm -f "$timestamp_file" "$current_snapshot"
        echo "Error: could not update last_updated in $target" >&2
        return 1
    fi
    rm -f "$current_snapshot"
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo " * Dry-run mode: whitelist files will not be modified" >&2
fi

STAGE_FAILURES=0
if [ "$DRY_RUN" -eq 1 ]; then
    if "$WHITELIST_ENGINE" --stage=all --dry-run --defer-timestamps; then
        :
    else
        STAGE_FAILURES=1
    fi
else
    for script in "$THIRD_PARTY_SCRIPT" "$CORE_SCRIPT" "$PLUGINS_SCRIPT" "$THEMES_SCRIPT"; do
        echo " * Running $(basename "$script")" >&2
        if "$script" --defer-timestamps; then
            :
        else
            STAGE_FAILURES=1
        fi
    done
fi

if [ "$DRY_RUN" -eq 0 ]; then
    TIMESTAMP_FAILURES=0
    SOURCE_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S.%6N') || {
        echo "Error: could not determine the current timestamp" >&2
        TIMESTAMP_FAILURES=1
    }
    if [ "$TIMESTAMP_FAILURES" -eq 0 ]; then
        update_timestamp_if_changed "$OFFICIAL_WHITELIST" "$OFFICIAL_SNAPSHOT" "$SOURCE_TIMESTAMP" || TIMESTAMP_FAILURES=1
        update_timestamp_if_changed "$THIRD_PARTY_WHITELIST" "$THIRD_PARTY_SNAPSHOT" "$SOURCE_TIMESTAMP" || TIMESTAMP_FAILURES=1
    fi
    if ! yara "$YARA_RULES" "$YARA_RULES" >/dev/null; then
        echo "Error: YARA rules failed to compile after trusted-source updates" >&2
        TIMESTAMP_FAILURES=1
    fi
    [ "$TIMESTAMP_FAILURES" -eq 0 ] || STAGE_FAILURES=1
fi

if yara -r "$YARA_RULES" "$WWWROOT" > "$MATCH_OUTPUT"; then
    :
else
    status=$?
    echo "Error: initial YARA scan failed with exit status $status" >&2
    exit "$status"
fi
if ! sed 's/^[^ ]* //' "$MATCH_OUTPUT" | sort -u > "$MATCHED_FILES"; then
    echo "Error: could not extract matched file paths" >&2
    exit 1
fi

while IFS= read -r file; do
    [ -n "$file" ] || continue
    case "$file" in
        *.php|*.PHP) ;;
        *) continue ;;
    esac
    if [ "$DRY_RUN" -eq 1 ]; then
        WHITELIST_HELPER="$CUSTOM_WHITELIST_HELPER" CUSTOM_WHITELIST="$CUSTOM_WHITELIST" \
            "$COMMENT_WHITELIST_SCRIPT" --dry-run "$file"
        status=$?
    else
        WHITELIST_HELPER="$CUSTOM_WHITELIST_HELPER" CUSTOM_WHITELIST="$CUSTOM_WHITELIST" \
            "$COMMENT_WHITELIST_SCRIPT" "$file"
        status=$?
    fi
    case "$status" in
        0|3) ;;
        *)
            echo "Error: comment-only verification failed for $file (exit status $status)" >&2
            exit "$status"
            ;;
    esac
done < "$MATCHED_FILES"

if yara -s -L -r "$YARA_RULES" "$WWWROOT" > "$MATCH_OUTPUT"; then
    :
else
    status=$?
    echo "Error: detailed YARA scan failed with exit status $status" >&2
    exit "$status"
fi
if ! "$PHP_BIN" "$YARA_OUTPUT_FILTER" --eligible-files "$MATCH_OUTPUT" > "$ELIGIBLE_FILES"; then
    echo "Error: could not classify NonPrintableChars matches" >&2
    exit 1
fi

if [ -s "$ELIGIBLE_FILES" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        while IFS= read -r file; do
            [ -n "$file" ] && echo " * Would add printable UTF-8-only match to custom whitelist: $file" >&2
        done < "$ELIGIBLE_FILES"
    elif ! "$CUSTOM_WHITELIST_HELPER" --files-from "$ELIGIBLE_FILES"; then
        echo "Error: could not add printable UTF-8-only matches to the custom whitelist" >&2
        exit 1
    fi
fi

exit "$STAGE_FAILURES"
