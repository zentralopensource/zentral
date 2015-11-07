# Zentral

Read the Wiki for Zentral overview and documentation: <https://github.com/zentralopensource/zentral/wiki>

For final documentation please bookmark: <http://zentral.readthedocs.org/en/latest/> 
- we currently work on migrating the doku to readthedocs. 

# Docker Containers

## Postgres container

You must run the PostgreSQL container before running the munkiwebadmin container.
Currently there is support only for PostgreSQL.
The supported way to run the container is using the [official postgres container](https://registry.hub.docker.com/u/library/postgres/) from the Docker Hub, but you can use your own. The app container expects the following environment variables to connect to a database:

DB_NAME
DB_USER
DB_PASS

```bash
$ docker pull postgres
$ docker run -d --name postgres-zentral \
    -e POSTGRES_DB=zentral \
    -e POSTGRES_USER=zentral \
    -e POSTGRES_PASSWORD=password \
    --volumes-from pgdata-zentral postgres
```

## Zentral Container
docker run -it --link postgres-zentral:db -e DB_PASS=password -e DB_NAME=zentral -e DB_USER=zentral  -p 8000:8000 zentral
