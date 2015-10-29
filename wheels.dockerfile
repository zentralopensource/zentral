FROM ubuntu:14.04

MAINTAINER Éric Falconnier <eric.falconnier@112hz.com>

# make the "en_US.UTF-8" locale so postgres will be utf-8 enabled by default
RUN apt-get update \
    && apt-get install -y locales \
    && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

# postgres
RUN apt-key adv --keyserver ha.pool.sks-keyservers.net --recv-keys B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
RUN echo 'deb http://apt.postgresql.org/pub/repos/apt/ trusty-pgdg main' > /etc/apt/sources.list.d/pgdg.list
RUN apt-get update \
    && apt-get install -y \
        python3-pip \
        postgresql-server-dev-9.4 \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install wheel

VOLUME /application
VOLUME /wheels

# Allez hop
ENTRYPOINT cd /application; pip3 wheel --wheel-dir /wheels -r requirements.txt
