FROM python:3.4
ENV PYTHONUNBUFFERED 1

MAINTAINER Éric Falconnier <eric.falconnier@112hz.com>

# cpio + bomutils + xar to generate the pkg files
# as seen in https://github.com/boot2docker/osx-installer/blob/master/Dockerfile
RUN apt-get update && apt-get autoremove -y && apt-get install -y cpio
RUN curl -fsSL https://github.com/hogliux/bomutils/archive/0.2.tar.gz | tar xvz && \
    cd bomutils-* && \
    make && make install && \
    cd .. && rm -rf bomutils-*
RUN curl -fsSL https://github.com/mackyle/xar/archive/xar-1.6.1.tar.gz | tar xvz && \
    cd xar-*/xar && \
    ./autogen.sh && ./configure && \
    make && make install && \
    cd ../.. && rm -rf xar-*

# app
RUN mkdir /zentral
WORKDIR /zentral
ADD requirements.txt /zentral
RUN pip install -r requirements.txt
ADD . /zentral
ENTRYPOINT ["/zentral/docker-entrypoint.py"]
