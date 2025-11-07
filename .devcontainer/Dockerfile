####
# Build stage 0:
# - Install apt build dependencies
# - Make venv and install requirements
#

FROM python:3.10-bookworm AS base-builder

# zentral apt dependencies
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends \
# extra dependencies for python crypto / WebAuthn
            libssl-dev \
            libffi-dev \
            python3-dev \
# dep for psycopg2
            libpq-dev \
# dep for python-ldap
            libldap2-dev \
            libsasl2-dev \
# dep to build the css and js dist files
            npm && \
# clean cache
    rm -rf /var/lib/apt/lists/*

# Create a virtualenv and use it
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -U pip setuptools wheel
ENV PATH="/opt/venv/bin:$PATH"

COPY constraints.txt requirements*.txt ./
RUN pip install -r requirements.txt -r requirements_dev.txt -r requirements_aws.txt -r requirements_gcp.txt

# Build the CSS and JS dist files
COPY package.json package-lock.json webpack.config.js ./
COPY server/static_src ./server/static_src
RUN npm install && npm run build