# Image for the Anthropic OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds it with the repository root as the build context, then audits /src with no network.
# Keep the base image and the dependencies in step with the Dockerfile at the root of the repository,
# and the services in step with docker-compose.yml and docker-compose.tests.yml.
FROM python:3.14-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    RABBITMQ_NODENAME=rabbit@localhost \
    PATH=/opt/venv/bin:$PATH

# Some networks cut the plain HTTP downloads of the large packages.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
        | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
        > /etc/apt/sources.list.d/clickhouse.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libbz2-dev libssl-dev libffi-dev libldap2-dev libsasl2-dev libcurl4-openssl-dev \
        libarchive-tools xmlsec1 npm locales \
        postgresql redis-server rabbitmq-server clickhouse-server clickhouse-client \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s' '<clickhouse><users><zentral_tests><password>zentral_tests</password>' \
        '<networks><ip>::/0</ip></networks><profile>default</profile><quota>default</quota>' \
        '<access_management>1</access_management></zentral_tests></users></clickhouse>' \
        > /etc/clickhouse-server/users.d/zentral_tests.xml

# The image of the root Dockerfile does not have this file, and the content type of the downloads depends on it.
RUN rm /etc/mime.types

# The collation of the postgres image in docker-compose.yml. The order of the lists in the tests depends on it.
RUN sed -i 's/^# *\(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen \
    && locale-gen \
    && version=$(pg_lsclusters --no-header | awk '{print $1}') \
    && pg_dropcluster "$version" main \
    && pg_createcluster --locale en_US.UTF-8 "$version" main

RUN set -eux; \
    url="https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.2.1-linux-$(uname -m).tar.gz"; \
    curl -fsSL --retry 5 --retry-all-errors -o /tmp/elasticsearch.tar.gz "$url"; \
    echo "$(curl -fsSL "$url.sha512" | cut -d ' ' -f 1)  /tmp/elasticsearch.tar.gz" | sha512sum -c -; \
    mkdir /opt/elasticsearch; \
    tar xzf /tmp/elasticsearch.tar.gz -C /opt/elasticsearch --strip-components=1; \
    rm /tmp/elasticsearch.tar.gz; \
    useradd --system --home-dir /opt/elasticsearch elasticsearch; \
    chown -R elasticsearch: /opt/elasticsearch

# mkbom and xar, to build the macOS packages
RUN set -eux; \
    cd /tmp; \
    curl -fsSL https://github.com/hogliux/bomutils/archive/c247002e2f49878bab32dd0fcf805810ae0992cb.tar.gz | tar xz; \
    (cd bomutils-* && make && make install); \
    curl -fsSL https://github.com/zentralopensource/xar/archive/f1578944c4539960053b5902951dbe5643478fbc.tar.gz | tar xz; \
    (cd xar-*/xar && ./autogen.sh && ./configure --with-bzip2 && make && make install); \
    ldconfig; \
    rm -rf /tmp/bomutils-* /tmp/xar-*

COPY requirements*.txt /tmp/requirements/
RUN python -m venv /opt/venv \
    && pip install -U pip setuptools wheel \
    && cd /tmp/requirements \
    && pip install -r requirements.txt -r requirements_dev.txt -r requirements_aws.txt -r requirements_gcp.txt \
    && rm -rf /tmp/requirements

# Scanner contract: the checkout lives inside the image, at /src.
COPY . /src
WORKDIR /src

# node_modules and the npm cache are third-party code, and are not necessary after the build.
RUN npm ci && npm run build && rm -rf node_modules && npm cache clean --force

# tests/conf/base.json refers to files below /zentral.
RUN ln -s /src /zentral \
    && mkdir /var/zentral \
    && ln -s /src/.oss-scanner/zentral-tests /usr/local/bin/zentral-tests

# Start the services once, and create the test database, so that the next runs with --keepdb do not apply the
# migrations again. Elasticsearch does not start on a data directory from an image layer.
RUN zentral-tests --build && rm -rf /opt/elasticsearch/data/*
