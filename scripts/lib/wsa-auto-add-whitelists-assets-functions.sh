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
