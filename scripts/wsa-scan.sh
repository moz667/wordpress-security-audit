#!/bin/sh

yara -r /usr/share/yara-rules/php.yar /var/www/html
