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
