## Build wheels builder image

docker build -t zentral/wheelsbuilder -f wheels.dockerfile .

## Build wheels

mkdir -p $(pwd)/wheels && docker run -v $(pwd)/wheels:/wheels -v $(pwd):/application zentral/wheelsbuilder

## Build zentral image

docker build -t zentral/zentral .

## Check zentral configuration

docker run -t -i zentral/zentral katze

## Run zentral image

docker run -t -i zentral/zentral

## Run zentral with a different conf

You can mount a local conf dir in the docker container to experiment with custom settings.

docker run -t -i -v path/to/your/conf/dir:/home/zentral/conf zentral/zentral

## Inspect the json_file action output

Mount a local dir as the json_file output dir in the container

docker run -t -i -v path/to/a/writable/dir:/tmp/zentral_notifications/

The notification files will be written in the host dir

## debug workers and daemons output

docker run -t -i -v path/to/a/writable/dir:/var/log/supervisor zentral/zentral
