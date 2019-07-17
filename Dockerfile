FROM python:3.7-buster
ENV PYTHONUNBUFFERED 1

MAINTAINER Éric Falconnier <eric.falconnier@112hz.com>

# zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
# xar to build the packages
            libbz2-dev \
# bsdcpio to generate the pkg files
            bsdcpio \
# xmlsec1 for PySAML2
            xmlsec1 \
# p7zip to extract dmg
            p7zip-full \
# extra dependencies for python crypto / u2f
            libssl-dev \
            libffi-dev \
            python3-dev && \
# clean cache
    rm -rf /var/lib/apt/lists/*

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

# zentral user and group
RUN groupadd -r zentral --gid=999 && \
    useradd -r -s /bin/false -g zentral --uid=999 zentral && \
    mkdir /home/zentral && chown zentral.zentral /home/zentral

# app
RUN mkdir /zentral
WORKDIR /zentral
ADD requirements.txt /zentral
RUN pip install -U pip && pip install -r requirements.txt
RUN mkdir /prometheus_sd && chown zentral:zentral /prometheus_sd
RUN mkdir /zentral_static && chown zentral:zentral /zentral_static
RUN mkdir /var/zentral && chown zentral:zentral /var/zentral
ADD . /zentral
USER zentral
ENTRYPOINT ["/zentral/docker-entrypoint.py"]
