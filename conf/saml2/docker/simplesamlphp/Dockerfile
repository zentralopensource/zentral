FROM php:7-apache

ENV SIMPLESAMLPHP_DOWNLOAD_URL https://github.com/simplesamlphp/simplesamlphp/releases/download/v1.14.11/simplesamlphp-1.14.11.tar.gz

RUN set -x \
    && mkdir -p /var/simplesamlphp \
    && curl -sSL "$SIMPLESAMLPHP_DOWNLOAD_URL" -o simplesamlphp.tar.gz \
    && tar -xzf simplesamlphp.tar.gz -C /var/simplesamlphp --strip-components=1 \
    && rm -rf simplesamlphp.tar.gz \
    && rm -rf /var/simplesamlphp/config \
    && rm -rf /var/simplesamlphp/cert \
    && rm -rf /var/simplesamlphp/metadata

ADD config /var/simplesamlphp/config
ADD cert /var/simplesamlphp/cert
ADD metadata /var/simplesamlphp/metadata

RUN touch /var/simplesamlphp/modules/exampleauth/enable

RUN a2dissite 000-default.conf
COPY vhost.conf /etc/apache2/sites-available/
RUN a2ensite vhost.conf
