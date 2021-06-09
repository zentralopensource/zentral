FROM golang:latest as build_container

WORKDIR /go/src/
RUN mkdir -p github.com/micromdm && \
    git clone https://github.com/micromdm/scep.git github.com/micromdm/scep
WORKDIR /go/src/github.com/micromdm/scep/
RUN GOOS=linux \
    GOARCH=$(go env GOHOSTARCH) \
    go build \
    -ldflags "-X main.version=$(git describe --tags --always --dirty)" \
    -o scepserver \
    ./cmd/scepserver


FROM debian:10-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq python3 vim openssl python3-pip

COPY --from=build_container /go/src/github.com/micromdm/scep/scepserver /usr/local/bin/scepserver

RUN groupadd -r scep --gid=999 && useradd -r -s /bin/false -g scep --uid=999 scep

ENV SCEP_FILE_DEPOT /var/lib/scep/CA
RUN mkdir -p $SCEP_FILE_DEPOT && \
    chown -R scep.scep $(dirname $SCEP_FILE_DEPOT)
VOLUME $SCEP_FILE_DEPOT

RUN mkdir -p /etc/scep/
ADD openssl.conf /etc/scep/

ADD requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt
ADD verify_zentral_csr.py /usr/local/bin
ENV SCEP_CSR_VERIFIER_EXEC /usr/local/bin/verify_zentral_csr.py

ADD docker-entrypoint.py /usr/local/bin/

USER scep:scep

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.py"]
CMD runserver
