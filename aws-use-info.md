# AWS + Basic Auth docker-compose

Pre-requisites:
- 1x Production certificate key file
- 1x Production certificate full chain file
  - (There should be 3 certificate blocks. Site, intermediary and root.)
- Site FQDN ie. `zentral.example.com`
- Admin email address
- Basic auth username and password
- 1x RDS Postgres database and accompanying configuration
- RDS Database FQDN ie. `db.example.com`
- Database name
- Database username and password

docker-compose-aws.yml is an extension of docker-compose-basic-auth.yml designed
for an EC2 host with RDS Postgres database.

- before starting, if you intend to make a private repo for your Zentral, please ensure you have initialised git appropriately.

- use `./prepare_for_aws.sh` and follow the command line prompts to change default
values to yours.

- the prepare_for_aws script will ask if you wish to rm the git cache afterwards. this is recommended as modifications have been made to .gitignore.

- use `docker-compose --file docker-compose-aws.yml up -d` to build zentral with a for AWS.
