FROM debian:trixie
# Keep in sync with the version the zentral.com build uses. The website mounts
# docs/content and docs/layouts into its own Hugo build, so a version skew here
# only shows up as a preview that renders differently from the published site.
ARG HUGO_VERSION="0.148.2"
ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
            ca-certificates \
            curl && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L -o hugo.deb "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_${HUGO_VERSION}_linux-${TARGETARCH}.deb" && \
    dpkg -i hugo.deb && \
    rm hugo.deb

WORKDIR /docs
EXPOSE 1313
CMD ["hugo", "server", "--bind=0.0.0.0", "--port=1313"]
