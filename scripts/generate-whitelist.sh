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

    echo "        // [START] Plugins whitelist rules"
    yara -r "$yara_rules_main_file" "$WWWROOT/wp-content/plugins" \
        | sed -e "s/.* //g" \
        | sed -E 's#^.*/wp-content/plugins/##; s#/.*##' \
        | sort -u \
        | while IFS= read -r plugin_dir; do
            [ -n "$plugin_dir" ] || continue

            plugin_path="$WWWROOT/wp-content/plugins/$plugin_dir"
            [ -d "$plugin_path" ] || continue

            name=$(grep -m1 "Plugin Name:" "$plugin_path"/*.php 2>/dev/null | head -n 1 | sed -E "s/.*Plugin Name:[[:space:]]*//; s/[[:space:]]*$//")
            ver=$(grep -m1 "Version:" "$plugin_path"/*.php 2>/dev/null | head -n 1 | sed -E "s/.*Version:[[:space:]]*//; s/[[:space:]]*$//")

            if [ -z "$name" ] || [ -z "$ver" ]; then
                echo "        // Plugin [$plugin_dir] skipped: missing Plugin Name/Version metadata"
                continue
            fi

            plugin_zip_url="https://downloads.wordpress.org/plugin/$plugin_dir.$ver.zip"
            wget -q "$plugin_zip_url"

            if [ -f "$plugin_dir.$ver.zip" ]; then
                unzip -q "$plugin_dir.$ver.zip"
                rm -f "$plugin_dir.$ver.zip"
                echo "        // Plugin [$name]"
                yara -r "$yara_rules_main_file" "/usr/local/share/src/wordpress/wp-content/plugins/$plugin_dir" \
                    | sed -e "s/.* /sha256sum /g" \
                    | sh \
                    | sed -e "s/ .*\/usr\/local\/share\/src\/wordpress\//\" or \/\/ /g" \
                          -e "s/^/        hash.sha256(0, filesize) == \"/g" \
                    | sort | uniq
                rm -rf "/usr/local/share/src/wordpress/wp-content/plugins/$plugin_dir"
            else
                echo "        // Plugin [$name] NOT FOUND on wordpress.org repository: $plugin_zip_url"
            fi
            echo ""
        done

    echo "        // [END] Plugins whitelist rules"

    echo "        // [END] Plugins whitelist rules"
fi
# [END] Plugins


# [START] Themes
if [ -d "$WWWROOT/wp-content/themes" ]; then
    mkdir -p /usr/local/share/src/wordpress/wp-content/themes
    cd /usr/local/share/src/wordpress/wp-content/themes

    echo "        // [START] Themes whitelist rules"
    find "$WWWROOT/wp-content/themes" -mindepth 2 -maxdepth 2 -type f -name 'style.css' \
    -exec sh -c '
        for f do
            grep -q "Theme Name:" "$f" || continue
            dir=$(basename "$(dirname "$f")")
            name=$(grep -m1 "Theme Name:" "$f" | sed -E "s/.*Theme Name:[[:space:]]*//; s/[[:space:]]*$//")
            ver=$(grep -m1 "Version:" "$f" | sed -E "s/.*Version:[[:space:]]*//; s/[[:space:]]*$//")
            
            theme_found="0"
            theme_zip_url="https://downloads.wordpress.org/theme/$dir.$ver.zip"
            wget -q $theme_zip_url
            if [ -f $dir.$ver.zip ]; then
                unzip -q $dir.$ver.zip
                rm $dir.$ver.zip
                theme_found="1"
            fi

            if [ "$theme_found" == "1" ]; then
                echo "        // Theme [$name]"
                yara -r $yara_rules_main_file /usr/local/share/src/wordpress/wp-content/themes/$dir | sed -e "s/.* /sha256sum /g" | sh | sed -e "s/ .*\/usr\/local\/share\/src\/wordpress\//\" or \/\/ /g" -e "s/^/        hash.sha256(0, filesize) == \"/g" | sort | uniq
            else
                echo "        // Theme [$name] NOT FOUND on wordpress.org repository: $theme_zip_url"
            fi
        done
    ' sh {} +

    echo "        // [END] Theme whitelist rules"
fi
# [END] Themes
