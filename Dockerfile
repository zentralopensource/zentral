FROM python:3.6
ENV PYTHONUNBUFFERED 1

MAINTAINER Éric Falconnier <eric.falconnier@112hz.com>

# bsdcpio + bomutils + xar to generate the pkg files
# as seen in https://github.com/boot2docker/osx-installer/blob/master/Dockerfile
RUN apt-get update && apt-get autoremove -y && apt-get install -y bsdcpio libbz2-dev
RUN curl -fsSL https://github.com/zentralopensource/bomutils/archive/master.tar.gz | tar xvz && \
    cd bomutils-* && \
    make && make install && \
    cd .. && rm -rf bomutils-*
RUN curl -fsSL https://github.com/mackyle/xar/archive/xar-1.6.1.tar.gz | tar xvz && \
    cd xar-*/xar && \
    ./autogen.sh && ./configure --with-bzip2 && \
    make && make install && \
    cd ../.. && rm -rf xar-*

# xmlsec1 for PySAML2
RUN apt-get install -y xmlsec1

# p7zip to extract dmg
RUN apt-get install -y p7zip-full

# extra dependencies for python crypto / u2f
RUN apt-get install -y libssl1.0-dev libffi-dev python-dev

# zentral user and group
RUN groupadd -r zentral --gid=999 && useradd -r -s /bin/false -g zentral --uid=999 zentral

# app
RUN mkdir /zentral
WORKDIR /zentral
ADD requirements.txt /zentral
RUN pip install -r requirements.txt
RUN mkdir /prometheus_sd && chown zentral:zentral /prometheus_sd
RUN mkdir /zentral_static && chown zentral:zentral /zentral_static
RUN mkdir /var/zentral && chown zentral:zentral /var/zentral
ADD . /zentral
USER zentral
ENTRYPOINT ["/zentral/docker-entrypoint.py"]
