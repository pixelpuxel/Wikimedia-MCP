#!/bin/sh
set -eu

password="$(cat /run/secrets/wiki_password)"
settings=/var/www/config/LocalSettings.php
runtime_settings=/var/www/html/LocalSettings.php

if [ ! -s "$settings" ]; then
    php /var/www/html/maintenance/install.php \
        --confpath /var/www/config \
        --dbtype sqlite \
        --dbpath /var/www/data \
        --dbname wikimedia-mcp \
        --server "${WIKI_PUBLIC_URL}" \
        --scriptpath "" \
        --lang de \
        --pass "$password" \
        "${WIKI_NAME:-Mein Wiki}" \
        "${WIKI_ADMIN_USER:-WikiMCP}"
    printf '\n' >> "$settings"
    cat /opt/LocalSettings.extra.php >> "$settings"
    chown www-data:www-data "$settings"
    chmod 0640 "$settings"
fi

ln -sfn "$settings" "$runtime_settings"
mkdir -p /var/www/data /var/www/config /var/www/html/images
chown -R www-data:www-data /var/www/data /var/www/config /var/www/html/images

exec docker-php-entrypoint "$@"
