################################################################################
# Build stage 0 `builder`:
################################################################################

FROM python:3.9-buster AS builder

# zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
# xar to build the packages
            libbz2-dev \
# extra dependencies for python crypto / u2f
            libssl-dev \
            libffi-dev \
            python3-dev \
# dep for python-ldap
            libldap2-dev \
            libsasl2-dev && \
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
RUN curl -fsSL https://github.com/zentralopensource/bomutils/archive/master.tar.gz | tar xvz && \
    cd bomutils-* && \
    make && make install && \
    cd .. && rm -rf bomutils-*
RUN curl -fsSL https://github.com/mackyle/xar/archive/xar-1.6.1.tar.gz | tar xvz && \
    cd xar-*/xar && \
    sed -i 's/OpenSSL_add_all_ciphers/CRYPTO_new_ex_data/' configure.ac && \
    ./autogen.sh && ./configure --with-bzip2 && \
    make && make install && \
    cd ../.. && rm -rf xar-*

# Create a virtualenv and use it
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -U pip setuptools wheel
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt


################################################################################
# Build stage 1:
# Copy tini and virtualenv from stage 0
# Add entrypoint
################################################################################

FROM python:3.9-slim
MAINTAINER Éric Falconnier <eric@zentral.pro>

# zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
# xar to build the packages
            libbz2-1.0 \
# bsdcpio to generate the pkg files
            bsdcpio \
# xmlsec1 for PySAML2
            xmlsec1 \
# extra dependencies for python crypto / u2f
            libssl1.1 \
            libffi6 \
# dep for python-ldap
            libldap-2.4-2 \
            libsasl2-2 && \
# clean cache
    rm -rf /var/lib/apt/lists/*

# zentral user and group
RUN groupadd -g 999 zentral && \
    useradd -u 999 -g 999 -m -d /zentral zentral

# copy files from builder
COPY --from=builder /tini /tini
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /usr/bin/mkbom /usr/bin/mkbom
COPY --from=builder /usr/local/lib/libxar.so.1 /usr/local/lib/libxar.so.1
COPY --from=builder /usr/local/bin/xar /usr/local/bin/xar

# app
COPY . /zentral

# mount points
RUN mkdir /prometheus_sd && chown zentral:zentral /prometheus_sd
RUN mkdir /zentral_static && chown zentral:zentral /zentral_static
RUN mkdir /var/zentral && chown zentral:zentral /var/zentral

WORKDIR /zentral
USER zentral
EXPOSE 8000
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["/zentral/docker-entrypoint.py"]
