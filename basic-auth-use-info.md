# htaccess basic auth docker-compose 

- use `docker-compose --file docker-compose-basic-auth.yml up -d` to build zentral with a basic htaccess protection for login

- default user/pass is test:test

Note:  please change your `zentral.htpasswd` file, i.e. generate yours like `htpasswd -nb username password`

