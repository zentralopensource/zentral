from django.db import migrations, models
from django.db.models import F


def set_scim_updated_at(apps, schema_editor):
    # updated_at changes at each login too, so this is an upper bound of the last SCIM write.
    # A realm user that SCIM made without an external ID gets the date at the next SCIM write.
    RealmUser = apps.get_model("realms", "RealmUser")
    RealmUser.objects.filter(scim_external_id__isnull=False).update(scim_updated_at=F("updated_at"))


class Migration(migrations.Migration):

    dependencies = [
        ('realms', '0015_realmgroup_scim_managed'),
    ]

    operations = [
        migrations.AddField(
            model_name='realmuser',
            name='scim_updated_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.RunPython(set_scim_updated_at, migrations.RunPython.noop),
    ]
