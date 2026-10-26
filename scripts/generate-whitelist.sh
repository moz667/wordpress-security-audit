#!/bin/sh

LATEST_WP_VERSION='7.1.3'

current_wp_version=$LATEST_WP_VERSION

if [ -f /var/www/html/wp-includes/version.php ]; then
    current_wp_version=$(grep "^\$wp_version\s*=" /var/www/html/wp-includes/version.php | awk -F\' '{print $2}')
fi

yara_rules_main_file="/usr/share/yara-rules/php.yar"

if [ "$LATEST_WP_VERSION" != "$current_wp_version" ]; then
    mkdir -p /usr/local/share/src
    cd /usr/local/share/src

    echo " * Downloading wordpress $current_wp_version..."
    wget -q https://wordpress.org/wordpress-$current_wp_version.zip
    sleep 1

    echo " * Unziping wordpress $current_wp_version..."
    unzip -q wordpress-$current_wp_version.zip

    echo "// [START] wordpress $current_wp_version"
    yara -r $yara_rules_main_file /usr/local/share/src/ | sed -e "s/.* /sha256sum /g" | sh | sed -e "s/ .*\/usr\/local\/share\/src\/wordpress\//\" or \/\/ /g" -e "s/^/        hash.sha256(0, filesize) == \"/g" | sort | uniq
    echo "// [END] wordpress $current_wp_version"
fi
