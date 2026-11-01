from django.db import migrations


def remove_the_superuser_flag_of_the_remote_users(apps, schema_editor):
    # a remote user only logs in through a realm, and a superuser logs in with a password only.
    # no check: each deployment verifies that it has a local superuser before the upgrade.
    User = apps.get_model("accounts", "User")
    User.objects.filter(is_remote=True, is_superuser=True).update(is_superuser=False)


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0024_alter_oidcapitokenissuer_cel_condition'),
    ]

    operations = [
        migrations.RunPython(remove_the_superuser_flag_of_the_remote_users, migrations.RunPython.noop),
    ]
