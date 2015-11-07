FROM ubuntu:latest

COPY requirements.txt /tmp/

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install -r /tmp/requirements.txt
RUN mkdir -p /home/zentral

COPY server /home/zentral/server
COPY zentral /home/zentral/zentral
COPY docker/conf /home/zentral/conf
COPY docker/version.py /home/zentral/server/server/
COPY docker/settings.py /home/zentral/server/server/

RUN python3 /home/zentral/server/manage.py collectstatic -v0 --noinput

COPY docker/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["python3", "/home/zentral/server/manage.py", "runserver", "0.0.0.0:8000"]
EXPOSE 8000

