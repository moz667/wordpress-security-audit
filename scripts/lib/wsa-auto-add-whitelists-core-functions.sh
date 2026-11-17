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
