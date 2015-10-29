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
    && apt-get install -y --no-install-recommends --no-install-suggests \
        postgresql-9.4 \
        postgresql-contrib-9.4 \
    && rm -rf /var/lib/apt/lists/*

# nginx
RUN apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62
RUN echo "deb http://nginx.org/packages/mainline/ubuntu/ trusty nginx" > /etc/apt/sources.list.d/nginx.list
RUN apt-get update \
    && apt-get install -y ca-certificates nginx \
    && rm -rf /var/lib/apt/lists/*

# apt dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        curl \
        memcached \
        python3 \
        python3-pip \
        redis-server \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

# Prometheus server
RUN curl -s -L -O https://github.com/prometheus/prometheus/releases/download/0.16.1/prometheus-0.16.1.linux-amd64.tar.gz \
    && tar xzf prometheus-0.16.1.linux-amd64.tar.gz -C /opt \
    && rm prometheus-0.16.1.linux-amd64.tar.gz \
    && mv /opt/prometheus-0.16.1.linux-amd64 /opt/prometheus \
    && mkdir -p /etc/prometheus/ \
    && mkdir -p /var/lib/prometheus/prometheus_data/
ADD docker/prometheus.yml /etc/prometheus/

# Prometheus push gateway
RUN curl -s -L -O https://github.com/prometheus/pushgateway/releases/download/0.2.0/pushgateway-0.2.0.linux-amd64.tar.gz \
    && tar xzf pushgateway-0.2.0.linux-amd64.tar.gz -C /opt \
    && rm pushgateway-0.2.0.linux-amd64.tar.gz \
    && mkdir -p /var/lib/prometheus/push_gateway_persistence_file

# Elasticsearch
RUN apt-key adv --keyserver ha.pool.sks-keyservers.net --recv-keys 46095ACC8548582C1A2699A9D27D666CD88E42B4
RUN echo "deb http://packages.elasticsearch.org/elasticsearch/1.7/debian stable main" > /etc/apt/sources.list.d/elasticsearch.list
RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        default-jdk \
        elasticsearch \
    && rm -rf /var/lib/apt/lists/*

# Kibana
RUN curl -s -L -O https://download.elastic.co/kibana/kibana/kibana-4.1.2-linux-x64.tar.gz \
    && tar xzf kibana-4.1.2-linux-x64.tar.gz -C /opt \
    && rm kibana-4.1.2-linux-x64.tar.gz \
    && mv /opt/kibana-4.1.2-linux-x64 /opt/kibana


# app
RUN mkdir /var/log/gunicorn && chown www-data.www-data /var/log/gunicorn
ADD docker/nginx/ssl /etc/nginx/ssl
ADD docker/nginx/nginx.conf /etc/nginx/
ADD docker/nginx/conf.d/zentral.conf /etc/nginx/conf.d/
ADD docker/supervisor.conf /etc/supervisor/supervisord.conf
ADD docker/redis.conf /etc/redis/redis.conf
ADD docker/pg_hba.conf /etc/postgresql/9.4/main/
RUN chown postgres.postgres /etc/postgresql/9.4/main/pg_hba.conf

RUN mkdir /home/zentral
ADD server /home/zentral/server
ADD zentral /home/zentral/zentral
ADD wheels /home/zentral/wheels
ADD requirements.txt /home/zentral/requirements.txt
RUN pip3 install --upgrade -r /home/zentral/requirements.txt --use-wheel --no-index --find-links=/home/zentral/wheels

ADD docker/conf /home/zentral/conf
ADD docker/version.py /home/zentral/server/server/
ADD docker/settings.py /home/zentral/server/server/

USER postgres
RUN  /usr/lib/postgresql/9.4/bin/pg_ctl start -w -D /etc/postgresql/9.4/main/ \
    && createuser zentral \
    && createdb -O zentral zentral \
    && createdb -O zentral zentral_events \
    && python3 /home/zentral/server/manage.py migrate \
    && /usr/lib/postgresql/9.4/bin/pg_ctl stop -w -D /etc/postgresql/9.4/main/
USER root
RUN python3 /home/zentral/server/manage.py collectstatic -v0 --noinput

# Allez hop
COPY docker/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 443
CMD ["run"]
