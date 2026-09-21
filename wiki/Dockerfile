FROM php@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d

ARG MEDIAWIKI_SHA256=08a676c392625cf3c5730a6c1b9390ab1e11dcc17cfd0ff97a2ae3917ef5a36a
ARG MOBILEFRONTEND_COMMIT=717861c608630d27f88d690a6515e85314f35470

RUN set -eux; \
    curl -fsSL -o /tmp/mediawiki.tar.gz https://releases.wikimedia.org/mediawiki/1.27/mediawiki-1.27.1.tar.gz; \
    echo "${MEDIAWIKI_SHA256}  /tmp/mediawiki.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/mediawiki.tar.gz -C /var/www/html --strip-components=1; \
    curl -fsSL -o /tmp/mobilefrontend.tar.gz "https://github.com/wikimedia/mediawiki-extensions-MobileFrontend/archive/${MOBILEFRONTEND_COMMIT}.tar.gz"; \
    mkdir -p /var/www/html/extensions/MobileFrontend; \
    tar -xzf /tmp/mobilefrontend.tar.gz -C /var/www/html/extensions/MobileFrontend --strip-components=1; \
    sed -i 's/"version": "1.0.0"/"version": "1.0.0 (717861c)"/' /var/www/html/extensions/MobileFrontend/extension.json; \
    rm /tmp/mediawiki.tar.gz /tmp/mobilefrontend.tar.gz; \
    a2enmod rewrite headers; \
    mkdir -p /var/www/data /var/www/config; \
    chown -R www-data:www-data /var/www/html /var/www/data /var/www/config

COPY apache-mediawiki.conf /etc/apache2/conf-available/mediawiki.conf
COPY entrypoint.sh /usr/local/bin/wikimedia-mcp-entrypoint
COPY LocalSettings.extra.php /opt/LocalSettings.extra.php
COPY uploads.ini /usr/local/etc/php/conf.d/uploads.ini
RUN set -eux; chmod 0755 /usr/local/bin/wikimedia-mcp-entrypoint; a2enconf mediawiki

ENTRYPOINT ["wikimedia-mcp-entrypoint"]
CMD ["apache2-foreground"]
