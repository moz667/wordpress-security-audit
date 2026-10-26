#!/bin/sh

# [START] Images
echo "        // [START] Custom whitelist rules"
echo ""
echo "        // Sanitized images"
yara -r /usr/share/yara-rules/php.yar /var/www/html | sed -e "s/.* //g" | sort | uniq | while read -r image; do
    if [ -f "$image" ] && identify "$image" >/dev/null 2>&1; then
        magick "$image" -flip -strip "$image"
        magick "$image" -flip "$image"

        echo $image | sed -e "s/^/sha256sum /g" | sh | sed -e "s/ .*\/var\/www\/html\\//\" or \/\/ /g" -e "s/^/        hash.sha256(0, filesize) == \"/g" | sort | uniq
    fi
done
echo ""
echo "        // [END] Custom whitelist rules"
# [END] Images