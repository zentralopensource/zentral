# Zentral deployment with docker-compose

This is a simple way of testing Zentral. Everything will run on the docker host.

## Requirements

* `Docker`, with the `docker-compose` command. [Docker Desktop for Mac](https://docs.docker.com/docker-for-mac/install/), for example.

* the default URL for zentral is `https://zentral`. The `zentral` name must resolve to the docker host. With Docker Desktop for Mac, it is `127.0.0.1`. Edit your `/etc/hosts` file.

## Setup

Download the source:

```bash
git clone https://github.com/zentralopensource/zentral
```

Build the `css` and `js` bundles. You need to have [`npm`](https://nodejs.org/en/download/) installed on your machine.

```bash
npm install && npm run build
```

_The step above is only required because the default docker deployment is configured for development. The bundles are mounted from the local disk, masking the ones pre-built in the container._

Build and launch all the containers in the background:

```bash
docker compose up -d
```

Wait until all the containers are created and started. You watch the `web` container logs with the following command:

```bash
docker compose logs -f --tail=100 web
```

You should see something like:

```
web_1       | Launch known command "runserver"
web_1       | 2019-06-28 15:57:36,383 PID25 autoreload INFO Watching for file changes with StatReloader
web_1       | Performing system checks...
web_1       |
web_1       | System check identified no issues (0 silenced).
web_1       | June 28, 2019 - 15:57:38
web_1       | Django version 2.2.2, using settings 'server.settings'
web_1       | Starting development server at http://0.0.0.0:8000/
web_1       | Quit the server with CONTROL-C.
```

At this point, the app is up and running.

Note: It is normal to see database migration errors. All the zentral containers are waiting for the database to come up, and try to apply the migrations. Only one need to succeed!



Create a Zentral superuser:

```bash
docker compose run --rm web createuser --superuser henry henry@zentral.pro
```

You should see something like that:

```bash
Launch known command "createuser"
Superuser henry henry@zentral.pro created
Password reset: https://zentral/reset/Mg/57k-ed34961f7af3efe96e8f/
```

Open the password reset link in a browser, set a password, and log in.

## Commands for docker-compose

Start everything:

```bash
docker compose up -d
```

Create (or promote) a superuser:

```bash
docker compose run --rm web createuser --superuser henry henry@zentral.com
```

Restart all the Zentral app containers (not the DB, Elasticsearch, …):

```bash
docker compose restart web workers celery
```

Update Zentral:

```bash
git pull && docker compose up -d web workers celery
```

List containers:

```bash
docker compose ps
```

Follow web logs:

```bash
docker compose logs -f web
```

Follow nginx logs:

```bash
docker compose logs -f nginx
```

Follow workers logs:

```
docker compose logs -f workers
```
