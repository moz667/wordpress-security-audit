#!/bin/sh

# [START] Wordpress core
LATEST_WP_VERSION='7.1.3'
current_wp_version=$LATEST_WP_VERSION

if [ -f /var/www/html/wp-includes/version.php ]; then
    current_wp_version=$(grep "^\$wp_version\s*=" /var/www/html/wp-includes/version.php | awk -F\' '{print $2}')
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
if [ -d /var/www/html/wp-content/plugins ]; then
    mkdir -p /usr/local/share/src/wordpress/wp-content/plugins
    cd /usr/local/share/src/wordpress/wp-content/plugins

    echo "        // [START] Plugins whitelist rules"
    find /var/www/html/wp-content/plugins -mindepth 2 -maxdepth 2 -type f -name '*.php' \
    -exec sh -c '
        for f do
            grep -q "Plugin Name:" "$f" || continue
            dir=$(basename "$(dirname "$f")")
            name=$(grep -m1 "Plugin Name:" "$f" | sed -E "s/.*Plugin Name:[[:space:]]*//; s/[[:space:]]*$//")
            ver=$(grep -m1 "Version:" "$f" | sed -E "s/.*Version:[[:space:]]*//; s/[[:space:]]*$//")
            
            plugin_found="0"
            plugin_zip_url="https://downloads.wordpress.org/plugin/$dir.$ver.zip"
            wget -q $plugin_zip_url
            if [ -f $dir.$ver.zip ]; then
                unzip -q $dir.$ver.zip
                rm $dir.$ver.zip
                plugin_found="1"
            fi

            if [ "$plugin_found" == "1" ]; then
                echo "        // Plugin [$name]"
                yara -r $yara_rules_main_file /usr/local/share/src/wordpress/wp-content/plugins/$dir | sed -e "s/.* /sha256sum /g" | sh | sed -e "s/ .*\/usr\/local\/share\/src\/wordpress\//\" or \/\/ /g" -e "s/^/        hash.sha256(0, filesize) == \"/g" | sort | uniq
            else
                echo "        // Plugin [$name] NOT FOUND on wordpress.org repository: $plugin_zip_url"
            fi
            echo ""
        done
    ' sh {} +

    echo "        // [END] Plugins whitelist rules"
fi
# [END] Plugins


# [START] Themes
if [ -d /var/www/html/wp-content/themes ]; then
    mkdir -p /usr/local/share/src/wordpress/wp-content/themes
    cd /usr/local/share/src/wordpress/wp-content/themes

    echo "        // [START] Themes whitelist rules"
    find /var/www/html/wp-content/themes -mindepth 2 -maxdepth 2 -type f -name 'style.css' \
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
