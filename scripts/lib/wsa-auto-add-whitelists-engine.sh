#!/bin/sh

# TODO: Add language-package handling to the source-appropriate whitelist and
# custom image rules from wsa-sanitize-images.sh to 99-custom.yar.

#
# Generate hash-based whitelist rules from trusted package archives.
# Rules are persisted as they are generated. Pass --dry-run to preview without
# changing whitelist files.
#
# Third-party archives are processed separately and never copied to CACHE_ROOT.
# CACHE_ROOT contains only packages downloaded from WordPress.org by this script.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WWWROOT="${WWWROOT:-/var/www/html}"
YARA_RULES="${YARA_RULES:-/usr/share/yara-rules/php.yar}"
THIRD_PARTY_ROOT="${THIRD_PARTY_ROOT:-/usr/local/share/src/third-party}"
CACHE_ROOT="${CACHE_ROOT:-/usr/share/cache/wordpress-security-audit}"
OFFICIAL_WHITELIST="${OFFICIAL_WHITELIST:-/usr/share/yara-rules/whitelists/10-oficial-repository.yar}"
THIRD_PARTY_WHITELIST="${THIRD_PARTY_WHITELIST:-/usr/share/yara-rules/whitelists/20-third-party.yar}"
STAGE="all"
DEFER_TIMESTAMPS=0

INDENT="        "
MODE="apply"
ERRORS=0
ERROR_COUNT=0
UNVERIFIED_FILES=0
RULES_ADDED=0
OFFICIAL_WHITELIST_CHANGED=0
THIRD_PARTY_WHITELIST_CHANGED=0

# ---------------------------------------------------------------------------
# Command-line arguments
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [--dry-run] [--defer-timestamps] [--stage=third-party|core|plugins|themes|all]

Generate whitelist rules from WordPress.org and third-party package archives.
Rules are saved as they are generated. Use --dry-run to preview without
changing whitelist files. Files that still match YARA are reported in the
summary and cause a non-zero exit status.
EOF
}

for argument in "$@"; do
    case "$argument" in
        --dry-run)
            MODE="dry-run"
            ;;
        --defer-timestamps)
            DEFER_TIMESTAMPS=1
            ;;
        --stage=third-party|--stage=core|--stage=plugins|--stage=themes|--stage=all)
            STAGE=${argument#--stage=}
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument: $argument" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    echo " * $*" >&2
}

comment() {
    echo "${INDENT}// $*"
}

report_error() {
    log "ERROR: $*"
    ERRORS=1
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

record_not_found_resource() {
    if [ -n "$3" ]; then
        printf '    - %s: %s %s: %s\n' "$1" "$2" "$3" "$4" >> "$NOT_FOUND_RESOURCES"
    else
        printf '    - %s: %s: %s\n' "$1" "$2" "$4" >> "$NOT_FOUND_RESOURCES"
    fi
}

sanitize_comment() {
    printf '%s' "$1" | tr '\r\n' '  ' | sed 's#\*/#* /#g'
}

# Print unique paths matched by the YARA rules under $1.
yara_matched_files() {
    local raw_matches

    raw_matches=$(mktemp "$WORK_DIR/matches.XXXXXX") || return 1
    if ! yara -r "$YARA_RULES" "$1" > "$raw_matches"; then
        rm -f "$raw_matches"
        return 1
    fi

    sed 's/^[^ ]* //' "$raw_matches" | sort -u
    rm -f "$raw_matches"
}

# Print hash rules for the files under $1 that still match the active YARA rules.
print_hash_rules() {
    local scan_dir="$1"
    local matched_files file hash line
    matched_files=$(mktemp "$WORK_DIR/matched-files.XXXXXX") || return 1

    if ! yara_matched_files "$scan_dir" > "$matched_files"; then
        rm -f "$matched_files"
        return 1
    fi

    while IFS= read -r file; do
        [ -f "$file" ] || continue
        if ! line=$(sha256sum "$file"); then
            rm -f "$matched_files"
            return 1
        fi
        hash=$(printf '%s\n' "$line" | awk '{print $1}')
        printf '%shash.sha256(0, filesize) == "%s" or // %s\n' \
            "$INDENT" "$hash" "${file#"$scan_dir"/}"
    done < "$matched_files"

    rm -f "$matched_files"
}

# Prints the value of the header field $2 (e.g. "Version") of file $1.
read_header() {
    sed -n '1,20p' "$1" \
        | grep -m1 "$2:" \
        | sed -E "s/.*$2:[[:space:]]*//; s/[[:space:]]*\*\/.*$//; s/[[:space:]]*$//"
}

# Find a plugin's main PHP file in directory $1.
find_plugin_main_file() {
    local php_file

    for php_file in "$1"/*.php; do
        [ -f "$php_file" ] || continue
        if sed -n '1,20p' "$php_file" | grep -q "Plugin Name:"; then
            echo "$php_file"
            return 0
        fi
    done
    return 1
}

# Reject unsafe ZIP paths before extracting into the temporary work directory.
validate_archive() {
    local archive="$1"
    local entries="$WORK_DIR/archive-entries"

    # BusyBox unzip (used in Alpine) has no -Z1 option; parse its portable -l output.
    if ! unzip -tq "$archive" >/dev/null 2>&1 ||
        ! unzip -lq "$archive" > "$entries"; then
        return 1
    fi

    awk '
        /^[[:space:]]*[0-9]+[[:space:]]+[0-9-]+[[:space:]]+[0-9:]+[[:space:]]+/ {
            entry = $0
            sub(/^[[:space:]]*[0-9]+[[:space:]]+[0-9-]+[[:space:]]+[0-9:]+[[:space:]]+/, "", entry)
            found = 1

            if (index(entry, "\\") || entry ~ /^\// || entry ~ /^[A-Za-z]:/) {
                invalid = 1
            }

            count = split(entry, parts, "/")
            for (i = 1; i <= count; i++) {
                if (parts[i] == "..") invalid = 1
            }
            next
        }
        END { exit invalid || !found }
    ' "$entries"
}

# Resolve an archive from third-party references, the official cache, or
# WordPress.org. Only official downloads are ever written to CACHE_ROOT.
find_archive() {
    local kind="$1" archive="$2" url="$3"
    local cache_dir="$CACHE_ROOT/$kind"
    local third_party_archive="$THIRD_PARTY_ROOT/$kind/$archive"

    if [ -s "$third_party_archive" ]; then
        archive_path="$third_party_archive"
        archive_source="third-party"
    elif [ -s "$cache_dir/$archive" ]; then
        archive_path="$cache_dir/$archive"
        archive_source="WordPress.org cache"
    else
        archive_path="$cache_dir/$archive"
        mkdir -p "$cache_dir" || return 1
        log "Downloading $url"
        if ! wget -q -O "$archive_path" "$url"; then
            rm -f "$archive_path"
            return 1
        fi
        archive_source="WordPress.org"
    fi

    if ! validate_archive "$archive_path"; then
        log "Invalid ZIP archive: $archive_path"
        if [ "$archive_source" = "WordPress.org" ]; then
            rm -f "$archive_path"
        fi
        return 1
    fi
}

# Persist one validated candidate whitelist while protecting concurrent edits.
persist_candidate_whitelist() {
    local candidate="$1" persistent snapshot temporary snapshot_temp

    case "$candidate" in
        "$CANDIDATE_OFFICIAL")
            persistent="$OFFICIAL_WHITELIST"
            snapshot="$ORIGINAL_OFFICIAL"
            ;;
        "$CANDIDATE_THIRD_PARTY")
            persistent="$THIRD_PARTY_WHITELIST"
            snapshot="$ORIGINAL_THIRD_PARTY"
            ;;
        *)
            report_error "unknown candidate whitelist: $candidate"
            return 1
            ;;
    esac

    [ "$MODE" = "dry-run" ] && return 0
    if ! cmp -s "$persistent" "$snapshot"; then
        report_error "whitelist changed during generation; refusing to overwrite $persistent"
        return 1
    fi

    temporary=$(mktemp "${persistent}.tmp.XXXXXX") || return 1
    snapshot_temp=$(mktemp "$WORK_DIR/whitelist-snapshot.XXXXXX") || {
        rm -f "$temporary"
        return 1
    }
    if ! cp -p "$persistent" "$temporary" ||
        ! cat "$candidate" > "$temporary" ||
        ! cp -p "$candidate" "$snapshot_temp"; then
        rm -f "$temporary" "$snapshot_temp"
        report_error "could not stage whitelist update for $persistent"
        return 1
    fi
    if ! mv "$temporary" "$persistent"; then
        rm -f "$temporary" "$snapshot_temp"
        report_error "could not save whitelist update to $persistent"
        return 1
    fi
    if ! mv "$snapshot_temp" "$snapshot"; then
        report_error "could not refresh the whitelist snapshot for $persistent"
        return 1
    fi
}

# Update the metadata after all rule blocks have been processed.
update_candidate_timestamp() {
    local target="$1" timestamp="$2"
    local temporary backup marker_count

    marker_count=$(awk '
        /^[[:space:]]*last_updated[[:space:]]*=/ { count++ }
        END { print count + 0 }
    ' "$target")
    if [ "$marker_count" -ne 1 ]; then
        report_error "expected exactly one last_updated field in $target"
        return 1
    fi

    temporary=$(mktemp "$WORK_DIR/whitelist-timestamp.XXXXXX") || return 1
    backup=$(mktemp "$WORK_DIR/whitelist-before-timestamp.XXXXXX") || {
        rm -f "$temporary"
        return 1
    }
    if ! cp -p "$target" "$backup" ||
        ! sed "s/^\([[:space:]]*last_updated[[:space:]]*=[[:space:]]*\)\"[^\"]*\"/\1\"$timestamp\"/" "$target" > "$temporary" ||
        ! grep -Fq "$timestamp" "$temporary" ||
        ! chmod "$(stat -c '%a' "$target")" "$temporary"; then
        rm -f "$temporary" "$backup"
        report_error "could not stage last_updated for $target"
        return 1
    fi
    if ! mv "$temporary" "$target"; then
        rm -f "$temporary" "$backup"
        report_error "could not update last_updated in $target"
        return 1
    fi
    if ! validate_candidate_rules; then
        cp -p "$backup" "$target"
        rm -f "$backup"
        return 1
    fi
    if ! persist_candidate_whitelist "$target"; then
        cp -p "$backup" "$target"
        rm -f "$backup"
        return 1
    fi

    rm -f "$backup"
    log "Updated last_updated in $(basename "$target")"
}

# Store one timestamp across all whitelists changed in this run.
finalize_whitelist_timestamps() {
    local timestamp status

    [ "$DEFER_TIMESTAMPS" -eq 0 ] || return 0
    if [ "$OFFICIAL_WHITELIST_CHANGED" -eq 0 ] && [ "$THIRD_PARTY_WHITELIST_CHANGED" -eq 0 ]; then
        return 0
    fi
    if [ "$MODE" = "dry-run" ]; then
        [ "$OFFICIAL_WHITELIST_CHANGED" -eq 0 ] ||
            log "Would update last_updated in $(basename "$CANDIDATE_OFFICIAL")"
        [ "$THIRD_PARTY_WHITELIST_CHANGED" -eq 0 ] ||
            log "Would update last_updated in $(basename "$CANDIDATE_THIRD_PARTY")"
        return 0
    fi

    timestamp=$(date '+%Y-%m-%dT%H:%M:%S.%6N') || {
        report_error "could not determine the current timestamp"
        return 1
    }
    status=0
    if [ "$OFFICIAL_WHITELIST_CHANGED" -eq 1 ]; then
        update_candidate_timestamp "$CANDIDATE_OFFICIAL" "$timestamp" || status=1
    fi
    if [ "$THIRD_PARTY_WHITELIST_CHANGED" -eq 1 ]; then
        update_candidate_timestamp "$CANDIDATE_THIRD_PARTY" "$timestamp" || status=1
    fi
    return "$status"
}

# Add newly generated rules to a candidate whitelist and persist each validated block.
add_rules_block() {
    local target="$1" category="$2" context="$3" rules_file="$4"
    local new_rules seen_hashes line hash block_file patched_file count backup marker_count

    new_rules=$(mktemp "$WORK_DIR/new-rules.XXXXXX") || return 1
    seen_hashes=$(mktemp "$WORK_DIR/seen-hashes.XXXXXX") || return 1
    : > "$new_rules"
    : > "$seen_hashes"

    while IFS= read -r line; do
        hash=$(printf '%s\n' "$line" | sed -n 's/.*== "\([0-9a-f]*\)".*/\1/p')
        [ -n "$hash" ] || continue

        if grep -Fq "\"$hash\"" "$target" || grep -Fq "$hash" "$seen_hashes"; then
            continue
        fi
        printf '%s\n' "$hash" >> "$seen_hashes"
        printf '%s\n' "$line" >> "$new_rules"
    done < "$rules_file"

    if [ ! -s "$new_rules" ]; then
        rm -f "$new_rules" "$seen_hashes"
        return 0
    fi
    count=$(awk 'END { print NR }' "$new_rules")

    context=$(sanitize_comment "$context")
    block_file=$(mktemp "$WORK_DIR/rule-block.XXXXXX") || return 1
    {
        comment "[START] $context"
        cat "$new_rules"
        comment "[END] $context"
        echo "${INDENT}"

    } > "$block_file"

    patched_file=$(mktemp "$WORK_DIR/patched-whitelist.XXXXXX") || return 1
    backup=$(mktemp "$WORK_DIR/whitelist-before-block.XXXXXX") || return 1
    if ! cp -p "$target" "$backup"; then
        rm -f "$new_rules" "$seen_hashes" "$block_file" "$patched_file" "$backup"
        report_error "could not snapshot candidate whitelist $target"
        return 1
    fi
    marker_count=$(awk -v block_file="$block_file" '
        index($0, "// End rule") {
            while ((getline line < block_file) > 0) print line
            close(block_file)
            markers++
        }
        { print }
        END {
            if (markers != 1) exit 1
        }
    ' "$target" > "$patched_file" && echo 1 || echo 0)
    if [ "$marker_count" != "1" ]; then
        rm -f "$new_rules" "$seen_hashes" "$block_file" "$patched_file" "$backup"
        report_error "expected exactly one '// End rule' marker in $target"
        return 1
    fi

    if ! chmod "$(stat -c '%a' "$target")" "$patched_file" || ! mv "$patched_file" "$target"; then
        rm -f "$new_rules" "$seen_hashes" "$block_file" "$patched_file" "$backup"
        report_error "could not update candidate whitelist $target"
        return 1
    fi
    if ! validate_candidate_rules; then
        cp -p "$backup" "$target"
        rm -f "$new_rules" "$seen_hashes" "$block_file" "$patched_file" "$backup"
        report_error "rejected invalid rules for $context"
        return 1
    fi
    if ! persist_candidate_whitelist "$target"; then
        cp -p "$backup" "$target"
        rm -f "$new_rules" "$seen_hashes" "$block_file" "$patched_file" "$backup"
        return 1
    fi

    RULES_ADDED=$((RULES_ADDED + count))
    case "$target" in
        "$CANDIDATE_OFFICIAL") OFFICIAL_WHITELIST_CHANGED=1 ;;
        "$CANDIDATE_THIRD_PARTY") THIRD_PARTY_WHITELIST_CHANGED=1 ;;
    esac
    if [ "$MODE" = "dry-run" ]; then
        log "Would add $count rule(s): $context"
    else
        log "Added $count rule(s): $context"
    fi

    rm -f "$new_rules" "$seen_hashes" "$block_file" "$patched_file" "$backup"
}

# Verify each file that triggered the initial scan against the candidate rules.
verify_baseline_matches() {
    local file output
    while IFS= read -r file; do
        [ -f "$file" ] || {
            UNVERIFIED_FILES=$((UNVERIFIED_FILES + 1))
            continue
        }
        output=$(mktemp "$WORK_DIR/file-scan.XXXXXX") || return 1
        if ! yara "$YARA_RULES" "$file" > "$output"; then
            rm -f "$output"
            report_error "YARA verification failed for $file"
            return 1
        fi
        if [ -s "$output" ]; then
            UNVERIFIED_FILES=$((UNVERIFIED_FILES + 1))
        fi
        rm -f "$output"
    done < "$BASELINE_MATCHES"
}

# Validate the full candidate YARA ruleset.
validate_candidate_rules() {
    local status
    if (cd "$CANDIDATE_RULES_DIR" && yara "$YARA_RULE_FILE" "$YARA_RULE_FILE" >/dev/null); then
        return 0
    else
        status=$?
        report_error "candidate YARA rules failed to compile (status $status)"
        return 1
    fi
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P) || exit 1
for source_file in \
    wsa-auto-add-whitelists-third-party-functions.sh \
    wsa-auto-add-whitelists-core-functions.sh \
    wsa-auto-add-whitelists-assets-functions.sh; do
    if [ ! -r "$SCRIPT_DIR/$source_file" ]; then
        echo "Error: whitelist source module not found: $SCRIPT_DIR/$source_file" >&2
        exit 1
    fi
    . "$SCRIPT_DIR/$source_file" || {
        echo "Error: could not load whitelist source module: $SCRIPT_DIR/$source_file" >&2
        exit 1
    }
done

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

for required_command in awk basename chmod cmp cp date find grep mkdir mktemp mv \
    rm sed sha256sum sort stat tr unzip wget yara; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "Error: required command not found: $required_command" >&2
        exit 1
    fi
done

[ -d "$WWWROOT" ] || {
    echo "Error: WordPress root does not exist: $WWWROOT" >&2
    exit 1
}
[ -f "$YARA_RULES" ] || {
    echo "Error: YARA rules not found: $YARA_RULES" >&2
    exit 1
}
[ -f "$OFFICIAL_WHITELIST" ] || {
    echo "Error: official whitelist not found: $OFFICIAL_WHITELIST" >&2
    exit 1
}
[ -f "$THIRD_PARTY_WHITELIST" ] || {
    echo "Error: third-party whitelist not found: $THIRD_PARTY_WHITELIST" >&2
    exit 1
}

RULES_DIR=$(cd "$(dirname "$YARA_RULES")" && pwd -P) || exit 1
YARA_RULE_FILE=$(basename "$YARA_RULES")
YARA_RULES="$RULES_DIR/$YARA_RULE_FILE"
OFFICIAL_WHITELIST=$(cd "$(dirname "$OFFICIAL_WHITELIST")" && pwd -P)/$(basename "$OFFICIAL_WHITELIST")
THIRD_PARTY_WHITELIST=$(cd "$(dirname "$THIRD_PARTY_WHITELIST")" && pwd -P)/$(basename "$THIRD_PARTY_WHITELIST")

case "$OFFICIAL_WHITELIST" in
    "$RULES_DIR"/*) OFFICIAL_RELATIVE=${OFFICIAL_WHITELIST#"$RULES_DIR"/} ;;
    *) echo "Error: official whitelist must be inside the YARA rules directory" >&2; exit 1 ;;
esac
case "$THIRD_PARTY_WHITELIST" in
    "$RULES_DIR"/*) THIRD_PARTY_RELATIVE=${THIRD_PARTY_WHITELIST#"$RULES_DIR"/} ;;
    *) echo "Error: third-party whitelist must be inside the YARA rules directory" >&2; exit 1 ;;
esac

WORK_DIR=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM
NOT_FOUND_RESOURCES="$WORK_DIR/not-found-resources"
: > "$NOT_FOUND_RESOURCES"

CANDIDATE_RULES_DIR="$WORK_DIR/rules"
mkdir "$CANDIDATE_RULES_DIR" || exit 1
if ! cp -R "$RULES_DIR"/. "$CANDIDATE_RULES_DIR"/; then
    echo "Error: could not stage YARA rules" >&2
    exit 1
fi
CANDIDATE_RULES_DIR=$(cd "$CANDIDATE_RULES_DIR" && pwd -P)
CANDIDATE_OFFICIAL="$CANDIDATE_RULES_DIR/$OFFICIAL_RELATIVE"
CANDIDATE_THIRD_PARTY="$CANDIDATE_RULES_DIR/$THIRD_PARTY_RELATIVE"
YARA_RULES="$CANDIDATE_RULES_DIR/$YARA_RULE_FILE"
ORIGINAL_OFFICIAL="$WORK_DIR/original-official"
ORIGINAL_THIRD_PARTY="$WORK_DIR/original-third-party"
cp -p "$OFFICIAL_WHITELIST" "$ORIGINAL_OFFICIAL" || exit 1
cp -p "$THIRD_PARTY_WHITELIST" "$ORIGINAL_THIRD_PARTY" || exit 1

BASELINE_MATCHES="$WORK_DIR/baseline-matches"
if ! yara_matched_files "$WWWROOT" > "$BASELINE_MATCHES"; then
    echo "Error: initial YARA scan failed" >&2
    exit 1
fi

if [ "$MODE" = "dry-run" ]; then
    log "Dry-run mode: whitelist files will not be modified"
else
    log "Whitelist rules will be persisted as they are generated"
fi

case "$STAGE" in
    all)
        process_third_party_catalog || ERRORS=1
        process_core || ERRORS=1
        process_installed_assets plugins Plugin || ERRORS=1
        process_installed_assets themes Theme || ERRORS=1
        ;;
    third-party)
        process_third_party_catalog || ERRORS=1
        ;;
    core)
        process_core || ERRORS=1
        ;;
    plugins)
        process_installed_assets plugins Plugin || ERRORS=1
        ;;
    themes)
        process_installed_assets themes Theme || ERRORS=1
        ;;
esac

if ! validate_candidate_rules; then
    ERRORS=1
fi

verify_baseline_matches || report_error "could not complete the verification scan"

finalize_whitelist_timestamps || ERRORS=1

if ! validate_candidate_rules; then
    ERRORS=1
fi

if [ "$MODE" = "dry-run" ]; then
    log "Summary (dry run): $RULES_ADDED rule(s) would be added; $UNVERIFIED_FILES file(s) remain unverified; $ERROR_COUNT error(s)"
else
    log "Summary: $RULES_ADDED rule(s) added; $UNVERIFIED_FILES file(s) remain unverified; $ERROR_COUNT error(s)"
fi

if [ -s "$NOT_FOUND_RESOURCES" ]; then
    log "Not found resources:"
    while IFS= read -r resource; do
        printf '%s\n' "$resource" >&2
    done < "$NOT_FOUND_RESOURCES"
fi

if [ "$ERRORS" -ne 0 ]; then
    exit 1
fi
