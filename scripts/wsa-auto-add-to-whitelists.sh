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
Usage: $(basename "$0") [--dry-run]

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

# Discover package name/version metadata in an extracted third-party archive.
archive_metadata() {
    local kind="$1" archive="$2" extract_dir="$3"
    local metadata_file name name_field version archive_base slug

    metadata_file=""
    if [ "$kind" = "plugins" ]; then
        metadata_file=$(find "$extract_dir" -type f -name '*.php' -print \
            | sort \
            | while IFS= read -r file; do
                if sed -n '1,20p' "$file" | grep -q "Plugin Name:"; then
                    echo "$file"
                    break
                fi
            done)
        name_field="Plugin Name"
    elif [ "$kind" = "themes" ]; then
        metadata_file=$(find "$extract_dir" -type f -name 'style.css' -print | sort | head -n 1)
        name_field="Theme Name"
    fi

    name=""
    version=""
    if [ -n "$metadata_file" ]; then
        name=$(read_header "$metadata_file" "$name_field" || true)
        version=$(read_header "$metadata_file" "Version" || true)
    fi

    archive_base=$(basename "$archive" .zip)
    slug="$archive_base"
    if [ -n "$version" ]; then
        case "$archive_base" in
            *."$version") slug=${archive_base%."$version"} ;;
        esac
    fi

    printf '%s\n%s\n%s\n' "${name:-$slug}" "$slug" "${version:-unknown}"
}

# Process every ZIP in the curated third-party catalog, whether or not its
# package is installed in the audited site.
process_third_party_catalog() {
    local archive_list archive kind extract_dir metadata name slug version rules_file

    [ -d "$THIRD_PARTY_ROOT" ] || return 0
    archive_list=$(mktemp "$WORK_DIR/third-party-archives.XXXXXX") || return 1
    if ! find "$THIRD_PARTY_ROOT" -type f -iname '*.zip' -print > "$archive_list"; then
        report_error "could not list third-party archives"
        rm -f "$archive_list"
        return 1
    fi
    sort -o "$archive_list" "$archive_list"

    while IFS= read -r archive; do
        [ -n "$archive" ] || continue
        case "$archive" in
            "$THIRD_PARTY_ROOT"/plugins/*) kind="plugins" ;;
            "$THIRD_PARTY_ROOT"/themes/*) kind="themes" ;;
            *) kind="third-party package" ;;
        esac

        log "Checking third-party archive $(basename "$archive")"
        if ! validate_archive "$archive"; then
            report_error "invalid third-party ZIP archive: $archive"
            continue
        fi

        extract_dir=$(mktemp -d "$WORK_DIR/third-party.XXXXXX") || return 1
        log "Extracting $(basename "$archive")"
        if ! unzip -q "$archive" -d "$extract_dir"; then
            report_error "could not extract third-party archive $archive"
            continue
        fi

        metadata=$(archive_metadata "$kind" "$archive" "$extract_dir")
        name=$(printf '%s\n' "$metadata" | sed -n '1p')
        slug=$(printf '%s\n' "$metadata" | sed -n '2p')
        version=$(printf '%s\n' "$metadata" | sed -n '3p')
        rules_file=$(mktemp "$WORK_DIR/third-party-rules.XXXXXX") || return 1
        if ! print_hash_rules "$extract_dir" > "$rules_file"; then
            report_error "YARA scan failed for third-party archive $archive"
            rm -f "$rules_file"
            continue
        fi

        if [ -s "$rules_file" ]; then
            context="$kind $name ($slug $version; source: third-party archive)"
            add_rules_block "$CANDIDATE_THIRD_PARTY" "third-party" "$context" "$rules_file" || true
        fi
        rm -f "$rules_file"
    done < "$archive_list"
    rm -f "$archive_list"
}

# Resolve and process the official/reference package for the installed WordPress core.
process_core() {
    local version_file="$WWWROOT/wp-includes/version.php"
    local version archive url extract_dir rules_file
    local core_candidates="$WORK_DIR/core-candidates" file relative_file
    local current_core_matches="$WORK_DIR/current-core-matches"

    : > "$core_candidates"
    while IFS= read -r file; do
        relative_file=${file#"$WWWROOT"/}
        case "$relative_file" in
            wp-admin/*|wp-includes/*)
                printf '%s\n' "$file" >> "$core_candidates"
                ;;
            */*)
                ;;
            wp-*.php|index.php|xmlrpc.php)
                printf '%s\n' "$file" >> "$core_candidates"
                ;;
        esac
    done < "$BASELINE_MATCHES"
    [ -s "$core_candidates" ] || return 0

    : > "$current_core_matches"
    while IFS= read -r file; do
        if ! yara_matched_files "$file" >> "$current_core_matches"; then
            report_error "YARA scan failed for $file"
            return 1
        fi
    done < "$core_candidates"
    [ -s "$current_core_matches" ] || {
        log "WordPress core findings are already covered by the third-party catalog"
        return 0
    }

    if [ ! -f "$version_file" ]; then
        log "Unable to detect the WordPress version; skipping core"
        return 0
    fi
    version=$(grep "^\$wp_version[[:space:]]*=" "$version_file" | awk -F\' '{print $2}')
    if [ -z "$version" ]; then
        log "Unable to detect the WordPress version; skipping core"
        return 0
    fi

    archive="wordpress-$version.zip"
    url="https://wordpress.org/$archive"
    log "Resolving WordPress core $version"
    if ! find_archive wordpress "$archive" "$url"; then
        record_not_found_resource "WordPress core" "wordpress-$version" "" "$url"
        report_error "WordPress core archive not found or invalid: $archive"
        return 1
    fi

    extract_dir=$(mktemp -d "$WORK_DIR/wordpress.XXXXXX") || return 1
    log "Extracting $archive"
    if ! unzip -q "$archive_path" -d "$extract_dir"; then
        report_error "could not extract WordPress core archive $archive"
        return 1
    fi
    rules_file=$(mktemp "$WORK_DIR/core-rules.XXXXXX") || return 1
    if ! print_hash_rules "$extract_dir" > "$rules_file"; then
        report_error "YARA scan failed for WordPress core $version"
        return 1
    fi
    if [ -s "$rules_file" ]; then
        if [ "$archive_source" = "third-party" ]; then
            add_rules_block "$CANDIDATE_THIRD_PARTY" third-party \
                "wordpress core $version (source: third-party archive)" "$rules_file" || return 1
        else
            add_rules_block "$CANDIDATE_OFFICIAL" official \
                "wordpress core $version (source: $archive_source)" "$rules_file" || return 1
        fi
    else
        log "No matching files in WordPress core $version"
    fi
    rm -f "$rules_file"
}

# Resolve an installed plugin or theme against the trusted archive sources.
process_asset() {
    local kind="$1" label="$2" asset_path="$3"
    local slug header_file name_field name version archive url extract_dir rules_file
    local source_category resource_type

    slug=$(basename "$asset_path")
    if [ "$kind" = "plugins" ]; then
        header_file=$(find_plugin_main_file "$asset_path" || true)
        name_field="Plugin Name"
        if [ -z "$header_file" ]; then
            log "$label $slug has no plugin header; skipping"
            return 0
        fi
    else
        header_file="$asset_path/style.css"
        name_field="Theme Name"
        if [ ! -f "$header_file" ]; then
            log "$label $slug has no style.css; skipping"
            return 0
        fi
    fi

    name=$(read_header "$header_file" "$name_field" || true)
    version=$(read_header "$header_file" "Version" || true)
    if [ -z "$name" ] || [ -z "$version" ]; then
        log "$label $slug has incomplete package metadata; skipping"
        return 0
    fi

    archive="$slug.$version.zip"
    url="https://downloads.wordpress.org/${kind%s}/$archive"
    log "Resolving $label $name $version"
    if ! find_archive "$kind" "$archive" "$url"; then
        resource_type=$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]')
        record_not_found_resource "$resource_type" "$slug" "$version" "$url"
        report_error "$label archive not found or invalid: $archive"
        return 1
    fi

    source_category="official"
    [ "$archive_source" = "third-party" ] && source_category="third-party"
    extract_dir=$(mktemp -d "$WORK_DIR/asset.XXXXXX") || return 1
    log "Extracting $archive"
    if ! unzip -q "$archive_path" -d "$extract_dir"; then
        report_error "could not extract $archive"
        return 1
    fi
    rules_file=$(mktemp "$WORK_DIR/asset-rules.XXXXXX") || return 1
    if ! print_hash_rules "$extract_dir" > "$rules_file"; then
        report_error "YARA scan failed for $label $name $version"
        return 1
    fi

    if [ -s "$rules_file" ]; then
        if [ "$source_category" = "third-party" ]; then
            add_rules_block "$CANDIDATE_THIRD_PARTY" third-party \
                "$label $name ($slug $version; source: third-party archive)" "$rules_file" || return 1
        else
            add_rules_block "$CANDIDATE_OFFICIAL" official \
                "$label $name ($slug $version; source: $archive_source)" "$rules_file" || return 1
        fi
    fi
    rm -f "$rules_file"
}

# Process only installed assets that were detected in the initial scan and still
# match after applying the third-party catalog rules.
process_installed_assets() {
    local kind="$1" label="$2" asset_root="$WWWROOT/wp-content/$1"
    local slugs slug asset_path matches
    [ -d "$asset_root" ] || return 0

    slugs=$(mktemp "$WORK_DIR/asset-slugs.XXXXXX") || return 1
    sed -E "s#^.*/wp-content/$kind/##; s#/.*##" "$BASELINE_MATCHES" \
        | sort -u > "$slugs"

    while IFS= read -r slug; do
        [ -n "$slug" ] || continue
        asset_path="$asset_root/$slug"
        [ -d "$asset_path" ] || continue

        matches=$(mktemp "$WORK_DIR/asset-matches.XXXXXX") || return 1
        if ! yara_matched_files "$asset_path" > "$matches"; then
            rm -f "$matches" "$slugs"
            report_error "YARA scan failed for $asset_path"
            return 1
        fi
        if [ -s "$matches" ]; then
            process_asset "$kind" "$label" "$asset_path" || ERRORS=1
        else
            log "$label $slug is already covered by the third-party catalog"
        fi
        rm -f "$matches"
    done < "$slugs"
    rm -f "$slugs"
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

process_third_party_catalog || ERRORS=1
process_core || ERRORS=1
process_installed_assets plugins Plugin || ERRORS=1
process_installed_assets themes Theme || ERRORS=1

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

if [ "$ERRORS" -ne 0 ] || [ "$UNVERIFIED_FILES" -ne 0 ]; then
    exit 1
fi
