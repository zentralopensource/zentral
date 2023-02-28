# ZAIO setup

On every _Zentral all in one_ instance, there is a setup script that will automatically take care of the last steps necessary to bring your Zentral instance online. Among them:

* get the server certificates and install them (letsencrypt)
* setup unique and random app secrets
* download and install the geo ip database
* create the first Zentral superuser

## How to run it

Once you are logged into your instance, use the following command:

```cmd
sudo /home/zentral/app/utils/setup.py \
     zentral.example.com \
     username \
     email@example.com
```

List of the arguments:

1. path to the install script. ALWAYS `/home/zentral/app/utils/setup.py`
2. **[required]** FQDN resolving to the public IP address of the instance. It has to be setup and it has to resolve correctly before running this script.
3. **[required]** username of the first Zentral superuser. It will be used to log into Zentral.
4. **[required]** email of the first Zentral superuser. It can be used for password recovery (if the instance can send emails, i.e., not on Google Cloud).

A lot of things will be happening. At the end of a successful run, you will get an invitation (password reset) for your superuser in the form of an URL:

```
Superuser username email@example.com created
Password reset: https://zentral.example.org/accounts/reset/MQ/xxx-xxxxxxxxxxxxxxxxx/
```

Open the invitation URL (Password reset) in your browser, pick a password, and log in with the username, and the new password. That's it!

## Troubleshooting

The script is built so that it can be run many times, in a non-destructive way. If you run into an error, you can re-run the script after fixing your setup.

Frequent issues:

* Check that at least the 22, 80 and 443 ports are not blocked by you network or instance settings.
* Check that the FQDN(s) do resolve to the public IP address of the instance.

## Extra tools

Some commands to manage your _Zentral all in one_ instance.


To restart the application, after having changed the configuration for example:

```bash
sudo /home/zentral/app/utils/reload_restart.sh
```

To deploy the main branch from the github repository:

```bash
sudo /home/zentral/app/utils/deploy.py
```

You can quickly see status for Zentral app, workers and celery worker:

```bash
sudo systemctl status zentral_web_app
sudo systemctl status zentral_workers
sudo systemctl status zentral_celery
```
