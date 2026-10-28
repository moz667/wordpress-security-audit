#!/bin/sh

WWWROOT="${WWWROOT:-/var/www/html}"

# [START] Wordpress core
LATEST_WP_VERSION='7.1.3'
current_wp_version=$LATEST_WP_VERSION

if [ -f "$WWWROOT/wp-includes/version.php" ]; then
    current_wp_version=$(grep "^\$wp_version\s*=" "$WWWROOT/wp-includes/version.php" | awk -F\' '{print $2}')
fi

yara_rules_main_file="/usr/share/yara-rules/php.yar"
export yara_rules_main_file

get_yara_matched_dirs() {
    target_dir="$1"
    marker_path="$2"

    [ -d "$target_dir" ] || return 0

    yara -r "$yara_rules_main_file" "$target_dir" 2>/dev/null \
        | sed -e "s/.* //g" \
        | sed -E "s#^.*/${marker_path}/##; s#/.*##" \
        | sort -u
}

process_whitelist_for_matches() {
    asset_type="$1"
    asset_root="$2"
    marker_path="$3"
    name_pattern="$4"
    version_pattern="$5"
    download_url_base="$6"
    extracted_root="$7"

    echo "        // [START] ${asset_type} whitelist rules"

    get_yara_matched_dirs "$asset_root" "$marker_path" \
        | while IFS= read -r asset_dir; do
            [ -n "$asset_dir" ] || continue

            asset_path="$asset_root/$asset_dir"
            [ -d "$asset_path" ] || continue

            if [ "$asset_type" = "Plugin" ]; then
                main_file=""
                for php_file in "$asset_path"/*.php; do
                    [ -f "$php_file" ] || continue
                    if sed -n '1,20p' "$php_file" | grep -Eq "Plugin Name:|Version:"; then
                        main_file="$php_file"
                        break
                    fi
                done

                [ -n "$main_file" ] || {
                    echo "        // Plugin [$asset_dir] skipped: no header metadata found in main PHP files"
                    continue
                }

                name=$(sed -n '1,20p' "$main_file" | grep -m1 "Plugin Name:" | sed -E "s/.*Plugin Name:[[:space:]]*//; s/[[:space:]]*$//")
                ver=$(sed -n '1,20p' "$main_file" | grep -m1 "Version:" | sed -E "s/.*Version:[[:space:]]*//; s/[[:space:]]*$//")
            else
                style_file="$asset_path/style.css"
                if [ ! -f "$style_file" ]; then
                    echo "        // Theme [$asset_dir] skipped: style.css not found"
                    continue
                fi

                name=$(sed -n '1,20p' "$style_file" | grep -m1 "Theme Name:" | sed -E "s/.*Theme Name:[[:space:]]*//; s/[[:space:]]*$//")
                ver=$(sed -n '1,20p' "$style_file" | grep -m1 "Version:" | sed -E "s/.*Version:[[:space:]]*//; s/[[:space:]]*$//")
            fi

            if [ -z "$name" ] || [ -z "$ver" ]; then
                echo "        // ${asset_type} [$asset_dir] skipped: missing metadata"
                continue
            fi

            zip_url="${download_url_base}/$asset_dir.$ver.zip"
            wget -q "$zip_url"

            if [ -f "$asset_dir.$ver.zip" ]; then
                unzip -q "$asset_dir.$ver.zip"
                rm -f "$asset_dir.$ver.zip"
                echo "        // ${asset_type} [$name]"
                yara -r "$yara_rules_main_file" "$extracted_root/$asset_dir" \
                    | sed -e "s/.* /sha256sum /g" \
                    | sh \
                    | sed -e "s/ .*${extracted_root//\//\\/}\//\" or \/\/ /g" \
                          -e "s/^/        hash.sha256(0, filesize) == \"/g" \
                    | sort | uniq
                rm -rf "$extracted_root/$asset_dir"
            else
                echo "        // ${asset_type} [$name] NOT FOUND on wordpress.org repository: $zip_url"
            fi
            echo ""
        done

    echo "        // [END] ${asset_type} whitelist rules"
}

if [ "$LATEST_WP_VERSION" != "$current_wp_version" ]; then
    mkdir -p /usr/local/share/src
    cd /usr/local/share/src

    echo " * Downloading wordpress $current_wp_version..."
    wget -q https://wordpress.org/wordpress-$current_wp_version.zip
    sleep 1

    echo " * Unziping wordpress $current_wp_version..."
    unzip -q wordpress-$current_wp_version.zip

    echo "        // [START] wordpress $current_wp_version"
    yara -r $yara_rules_main_file /usr/local/share/src/ | sed -e "s/.* /sha256sum /g" | sh | sed -e "s/ .*\/usr\/local\/share\/src\/wordpress\//\" or \/\/ /g" -e "s/^/        hash.sha256(0, filesize) == \"/g" | sort | uniq
    echo "        // [END] wordpress $current_wp_version"
fi
# [END] Wordpress core

# [START] Plugins
if [ -d "$WWWROOT/wp-content/plugins" ]; then
    mkdir -p /usr/local/share/src/wordpress/wp-content/plugins
    cd /usr/local/share/src/wordpress/wp-content/plugins

    process_whitelist_for_matches \
        "Plugin" \
        "$WWWROOT/wp-content/plugins" \
        "wp-content/plugins" \
        "Plugin Name" \
        "Version" \
        "https://downloads.wordpress.org/plugin" \
        "/usr/local/share/src/wordpress/wp-content/plugins"
fi
# [END] Plugins


# [START] Themes
if [ -d "$WWWROOT/wp-content/themes" ]; then
    mkdir -p /usr/local/share/src/wordpress/wp-content/themes
    cd /usr/local/share/src/wordpress/wp-content/themes

    process_whitelist_for_matches \
        "Theme" \
        "$WWWROOT/wp-content/themes" \
        "wp-content/themes" \
        "Theme Name" \
        "Version" \
        "https://downloads.wordpress.org/theme" \
        "/usr/local/share/src/wordpress/wp-content/themes"
fi
# [END] Themes
