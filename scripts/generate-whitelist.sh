#!/bin/sh
#
# Generates YARA whitelist rules (sha256 hashes) for the WordPress core,
# plugin and theme files of $WWWROOT that trigger the php.yar rules, using
# the original packages as reference.
#
# Rules are printed to stdout, ready to be pasted between the [START]/[END]
# markers of yara-rules/whitelists/*.yar. Progress messages go to stderr.
#
# Archives are resolved in this order:
#   1. $THIRD_PARTY_ROOT/<kind>/<archive>   (vendored, read-only)
#   2. $CACHE_ROOT/<kind>/<archive>         (previous downloads)
#   3. WordPress.org                         (stored in the cache if valid)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WWWROOT="${WWWROOT:-/var/www/html}"
YARA_RULES="/usr/share/yara-rules/php.yar"

# WordPress version already covered by whitelists/wordpress.yar
LATEST_WP_VERSION="7.1.3"

THIRD_PARTY_ROOT="/usr/local/share/src/third-party"
CACHE_ROOT="/usr/share/cache/wordpress-security-audit"

INDENT="        "

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    echo " * $*" >&2
}

# Prints a YARA comment line
comment() {
    echo "${INDENT}// $*"
}

# Prints the paths of the files under $1 matched by the YARA rules
yara_matched_files() {
    yara -r "$YARA_RULES" "$1" \
        | sed 's/^[^ ]* //' \
        | sort -u
}

# Prints a whitelist condition for every matched file under $1, commented
# with its path relative to $2
print_hash_rules() {
    local scan_dir="$1" base_dir="$2"

    yara_matched_files "$scan_dir" | while IFS= read -r file; do
        [ -f "$file" ] || continue
        printf '%shash.sha256(0, filesize) == "%s" or // %s\n' \
            "$INDENT" \
            "$(sha256sum "$file" | cut -d' ' -f1)" \
            "${file#"$base_dir"/}"
    done | sort -u
}

# Prints the value of the header field $2 (e.g. "Version") of file $1
read_header() {
    sed -n '1,20p' "$1" \
        | grep -m1 "$2:" \
        | sed -E "s/.*$2:[[:space:]]*//; s/[[:space:]]*$//"
}

# Prints the main file of the plugin in directory $1 (the PHP file with
# the "Plugin Name:" header)
find_plugin_main_file() {
    local php_file

    for php_file in "$1"/*.php; do
        [ -f "$php_file" ] || continue
        if sed -n '1,20p' "$php_file" | grep -q "Plugin Name:"; then
            echo "$php_file"
            return
        fi
    done
}

# Looks up archive $2 of kind $1 (plugins|themes|wordpress), downloading it
# from $3 if needed. On success sets $archive_path and $archive_source.
find_archive() {
    local kind="$1" archive="$2" url="$3"
    local cache_dir="$CACHE_ROOT/$kind"

    if [ -s "$THIRD_PARTY_ROOT/$kind/$archive" ]; then
        archive_path="$THIRD_PARTY_ROOT/$kind/$archive"
        archive_source="third-party"
        return 0
    fi

    archive_path="$cache_dir/$archive"

    if [ -s "$archive_path" ]; then
        archive_source="cached"
        return 0
    fi

    archive_source="downloaded"
    mkdir -p "$cache_dir"

    if wget -q -O "$archive_path" "$url" && unzip -tq "$archive_path" >/dev/null 2>&1; then
        return 0
    fi

    # Never cache broken or empty downloads
    rm -f "$archive_path"
    return 1
}

# ---------------------------------------------------------------------------
# WordPress core
# ---------------------------------------------------------------------------

process_core() {
    local version_file="$WWWROOT/wp-includes/version.php"
    local version="$LATEST_WP_VERSION"
    local archive url

    if [ -f "$version_file" ]; then
        version=$(grep "^\$wp_version[[:space:]]*=" "$version_file" | awk -F\' '{print $2}')
    fi

    if [ -z "$version" ]; then
        log "Unable to detect the WordPress version, skipping core"
        return
    fi

    if [ "$version" = "$LATEST_WP_VERSION" ]; then
        log "WordPress $version is already whitelisted, skipping core"
        return
    fi

    archive="wordpress-$version.zip"
    url="https://wordpress.org/$archive"

    log "Fetching WordPress $version..."
    if ! find_archive "wordpress" "$archive" "$url"; then
        comment "WordPress [$version] NOT FOUND: $url"
        return
    fi

    log "Unzipping WordPress $version ($archive_source)..."
    unzip -q -o "$archive_path" -d "$WORK_DIR"

    comment "[START] wordpress $version"
    print_hash_rules "$WORK_DIR/wordpress" "$WORK_DIR/wordpress"
    comment "[END] wordpress $version"

    rm -rf "$WORK_DIR/wordpress"
}

# ---------------------------------------------------------------------------
# Plugins & themes
# ---------------------------------------------------------------------------

# Generates the rules for the plugin/theme in directory $3
#   $1: kind  (plugins|themes)
#   $2: label (Plugin|Theme)
#   $3: asset directory
#   $4: directory where the original archive is extracted
process_asset() {
    local kind="$1" label="$2" asset_path="$3" extract_dir="$4"
    local slug header_file name_field name version archive url

    slug=$(basename "$asset_path")

    if [ "$kind" = "plugins" ]; then
        header_file=$(find_plugin_main_file "$asset_path")
        name_field="Plugin Name"

        if [ -z "$header_file" ]; then
            comment "$label [$slug] skipped: no header metadata found in main PHP files"
            return
        fi
    else
        header_file="$asset_path/style.css"
        name_field="Theme Name"

        if [ ! -f "$header_file" ]; then
            comment "$label [$slug] skipped: style.css not found"
            return
        fi
    fi

    name=$(read_header "$header_file" "$name_field")
    version=$(read_header "$header_file" "Version")

    if [ -z "$name" ] || [ -z "$version" ]; then
        comment "$label [$slug] skipped: missing metadata"
        return
    fi

    archive="$slug.$version.zip"
    url="https://downloads.wordpress.org/${kind%s}/$archive"

    if ! find_archive "$kind" "$archive" "$url"; then
        comment "$label [$name] NOT FOUND on wordpress.org repository: $url"
        return
    fi

    comment "$label [$name] using $archive_source archive: $archive_path"
    unzip -q -o "$archive_path" -d "$extract_dir"

    comment "$label [$name]"
    print_hash_rules "$extract_dir/$slug" "$extract_dir"

    rm -rf "${extract_dir:?}/$slug"
}

# Generates the rules for every plugin/theme with at least one YARA match
#   $1: kind  (plugins|themes)
#   $2: label (Plugin|Theme)
process_assets() {
    local kind="$1" label="$2"
    local asset_root="$WWWROOT/wp-content/$kind"
    local extract_dir="$WORK_DIR/$kind"

    [ -d "$asset_root" ] || return 0
    mkdir -p "$extract_dir"

    comment "[START] $label whitelist rules"

    yara_matched_files "$asset_root" \
        | sed -E "s#^.*/wp-content/$kind/##; s#/.*##" \
        | sort -u \
        | while IFS= read -r slug; do
            [ -n "$slug" ] && [ -d "$asset_root/$slug" ] || continue

            process_asset "$kind" "$label" "$asset_root/$slug" "$extract_dir"
            echo ""
        done

    comment "[END] $label whitelist rules"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

WORK_DIR=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

process_core
process_assets "plugins" "Plugin"
process_assets "themes" "Theme"
