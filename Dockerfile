FROM python:3.4
ENV PYTHONUNBUFFERED 1

MAINTAINER Éric Falconnier <eric.falconnier@112hz.com>

# app code
RUN mkdir /zentral
WORKDIR /zentral
ADD requirements.txt /zentral
RUN pip install -r requirements.txt
ADD . /zentral
ENTRYPOINT ["/zentral/docker-entrypoint.py"]
ADD examples/conf /zentral
