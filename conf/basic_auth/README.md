# htaccess basic auth docker-compose 

use `docker-compose -f docker-compose.yml -f docker-compose.basic-auth.yml up -d` to run zentral with a basic htaccess protection for login

default user/pass is test:test

Please change your `conf/basic_auth/docker/nginx/extra/zentral.htpasswd` file, i.e. generate yours like `htpasswd -nb username password`
