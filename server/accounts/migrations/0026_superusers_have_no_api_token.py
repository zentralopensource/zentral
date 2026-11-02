from django.db import migrations


def delete_the_api_tokens_of_the_superusers(apps, schema_editor):
    # a superuser skips PBAC: its API token would be a credential that no policy bounds.
    # the authentication already refuses these tokens, the CHANGELOG gives the query to list them.
    APIToken = apps.get_model("accounts", "APIToken")
    APIToken.objects.filter(user__is_superuser=True, user__is_service_account=False).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0025_remote_users_are_not_superusers'),
    ]

    operations = [
        migrations.RunPython(delete_the_api_tokens_of_the_superusers, migrations.RunPython.noop),
    ]
