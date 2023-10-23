# Defining environment
ARG APP_ENV=dev
ARG APP_VERSION=unknown


####
# Build stage 0:
# - Install apt build dependencies
# - Download and build tini
# - Download and build bomutils and xar
# - Make venv and install common requirements
#

FROM python:3.10-bookworm AS base-builder

# zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
# xar to build the packages
            libbz2-dev \
# extra dependencies for python crypto / WebAuthn
            libssl-dev \
            libffi-dev \
            python3-dev \
# dep for psycopg2
            libpq-dev \
# dep for pylibmc
            libmemcached-dev \
# dep for python-ldap
            libldap2-dev \
            libsasl2-dev \
# dep to build the css and js dist files
            npm && \
# clean cache
    rm -rf /var/lib/apt/lists/*

# tini
# see https://github.com/elastic/dockerfiles/blob/23f38a8a9f825c21784a02dde18dea0e54c88bbc/elasticsearch/Dockerfile#L21
RUN set -eux ; \
    \
    tini_bin="" ; \
    case "$(arch)" in \
        aarch64) tini_bin='tini-arm64' ;; \
        x86_64)  tini_bin='tini-amd64' ;; \
        *) echo >&2 ; echo >&2 "Unsupported architecture $(arch)" ; echo >&2 ; exit 1 ;; \
    esac ; \
    curl --retry 8 -S -L -O https://github.com/krallin/tini/releases/download/v0.19.0/${tini_bin} ; \
    curl --retry 8 -S -L -O https://github.com/krallin/tini/releases/download/v0.19.0/${tini_bin}.sha256sum ; \
    sha256sum -c ${tini_bin}.sha256sum ; \
    rm ${tini_bin}.sha256sum ; \
    mv ${tini_bin} /tini ; \
    chmod +x /tini

# bomutils & xar build (to generate the pkg files with zentral)
# as seen in https://github.com/boot2docker/osx-installer/blob/master/Dockerfile
RUN set -eux ; \
    \
    curl -fsSL https://github.com/zentralopensource/bomutils/archive/master.tar.gz | tar xvz ; \
    cd bomutils-* ; \
    make ; make install ; \
    cd .. ; rm -rf bomutils-*
RUN set -eux ; \
    \
    curl -fsSL https://github.com/mackyle/xar/archive/xar-1.6.1.tar.gz | tar xvz; \
    cd xar-*/xar ; \
    sed -i 's/OpenSSL_add_all_ciphers/CRYPTO_new_ex_data/' configure.ac ; \
    curl -L -o config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD' ; \
    ./autogen.sh && ./configure --with-bzip2 ; \
    if [ "$(arch)" = "aarch64" ] ; then \
      sed -i 's/CPPFLAGS :=/CPPFLAGS := -fsigned-char/' Makefile ; \
      sed -i 's/CFLAGS :=/CFLAGS := -fsigned-char/' Makefile ; \
    fi ; \
    make ; make install ; \
    cd ../.. ; rm -rf xar-*

# Create a virtualenv and use it
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -U pip setuptools wheel
ENV PATH="/opt/venv/bin:$PATH"

COPY constraints.txt requirements.txt ./
RUN pip install -r requirements.txt

# Build the CSS and JS dist files
COPY package.json package-lock.json webpack.config.js ./
COPY server/static_src ./server/static_src
RUN npm install && npm run build


####
# Build stage 1:
# - install extra APP_ENV requirements
#

# Installing the extra requirements for dev
FROM base-builder as dev-builder
COPY constraints.txt requirements_*.txt ./
RUN pip install -r requirements_dev.txt -r requirements_aws.txt -r requirements_gcp.txt


# Installing the extra requirements for aws
FROM base-builder as aws-builder
COPY constraints.txt requirements_aws.txt ./
RUN pip install -r requirements_aws.txt


# Installing the extra requirements for gcp
FROM base-builder as gcp-builder
COPY constraints.txt requirements_gcp.txt ./
RUN pip install -r requirements_gcp.txt


#####
# Build stage 2:
# - install apt dependencies
# - add zentral user & home
# - create common app dirs
# - copy tini, mkbom and xar from stage 0
#

FROM python:3.10-slim-bookworm as base-runner

# zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
# xar to build the packages
            libbz2-1.0 \
# bsdcpio to generate the pkg files
            libarchive-tools \
# xmlsec1 for PySAML2
            xmlsec1 \
# libpq5 for psycopg2
            libpq5 \
# extra dependencies for python crypto / WebAuthn
            libssl3 \
            libffi8 \
# dep for python-ldap
            libldap-2.5-0 \
            libsasl2-2 && \
# clean cache
    rm -rf /var/lib/apt/lists/*

# zentral user and group
RUN groupadd -g 999 zentral && \
    useradd -u 999 -g 999 -m -d /zentral zentral

# common app dirs
RUN mkdir /zentral_static && chown zentral:zentral /zentral_static
RUN mkdir /var/zentral && chown zentral:zentral /var/zentral

# copy files from builder
COPY --from=base-builder /tini /tini
COPY --from=base-builder /usr/bin/mkbom /usr/bin/mkbom
COPY --from=base-builder /usr/local/lib/libxar.so.1 /usr/local/lib/libxar.so.1
COPY --from=base-builder /usr/local/bin/xar /usr/local/bin/xar


####
# Build stage 3:
# - run extra APP_ENV setup
# - copy venv from APP_ENV builder
#

FROM base-runner as dev-runner
COPY ./tests /zentral/tests
RUN mkdir /prometheus_sd && chown zentral:zentral /prometheus_sd
COPY --from=dev-builder /opt/venv /opt/venv
# extra zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
            # pycurl for kombu[sqs]
            libcurl4-openssl-dev \
            # for pylibmc
            libmemcached11 && \
# clean cache
    rm -rf /var/lib/apt/lists/*


FROM base-runner as aws-runner
COPY --from=aws-builder /opt/venv /opt/venv
# extra zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
            # pycurl for kombu[sqs]
            libcurl4-openssl-dev \
            # for pylibmc
            libmemcached11 && \
# clean cache
    rm -rf /var/lib/apt/lists/*


FROM base-runner as gcp-runner
COPY --from=gcp-builder /opt/venv /opt/venv


####
# Build stage 4:
# - copy the app
# - set workdir, user, port, env, and entrypoint
#

FROM ${APP_ENV}-runner as final
ARG APP_VERSION
LABEL maintainer="Éric Falconnier <eric@zentral.com>"

COPY docker-entrypoint.py /zentral/
COPY ./ee /zentral/ee
COPY ./server /zentral/server
COPY ./zentral /zentral/zentral
COPY --from=base-builder /server/static/dist /zentral/server/static/dist
RUN printf "version = \"\"\"$APP_VERSION\"\"\"\n" > /zentral/server/base/deployment.py

WORKDIR /zentral
USER zentral
EXPOSE 8000
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["/tini", "--", "/zentral/docker-entrypoint.py"]
