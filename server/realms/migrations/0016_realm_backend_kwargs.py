from django.db import migrations, models

from zentral.core.secret_engines import encrypt_str


BACKEND_SECRET_KEYS = {
    "ldap": "bind_password",
    "openidc": "client_secret",
}


def dedupe_realm_names(apps, schema_editor):
    Realm = apps.get_model("realms", "Realm")
    seen_names = set()
    for realm in Realm.objects.all().order_by("created_at", "uuid"):
        name = realm.name
        suffix = 1
        while name in seen_names:
            suffix += 1
            # truncated to fit in the varchar(255) column, widened only in the next operation
            name = f"{realm.name[:240]} ({suffix})"
        if name != realm.name:
            realm.name = name
            realm.save()
        seen_names.add(name)


def encrypt_realm_secrets(apps, schema_editor):
    Realm = apps.get_model("realms", "Realm")
    for realm in Realm.objects.all():
        secret_key = BACKEND_SECRET_KEYS.get(realm.backend)
        if not secret_key:
            continue
        secret = realm.backend_kwargs.get(secret_key)
        if not secret:
            continue
        realm.backend_kwargs[secret_key] = encrypt_str(
            secret, field=secret_key, model="realms.realm", pk=str(realm.pk)
        )
        realm.save()


class Migration(migrations.Migration):

    dependencies = [
        ('realms', '0015_realmgroup_scim_managed'),
    ]

    operations = [
        migrations.AddField(
            model_name='realm',
            name='description',
            field=models.TextField(blank=True),
        ),
        migrations.RunPython(dedupe_realm_names),
        migrations.AlterField(
            model_name='realm',
            name='name',
            field=models.CharField(unique=True),
        ),
        migrations.AlterField(
            model_name='realm',
            name='backend',
            field=models.CharField(
                choices=[('ldap', 'LDAP'), ('openidc', 'OpenID Connect'), ('saml', 'SAML')],
                editable=False,
                max_length=255,
            ),
        ),
        migrations.RenameField(
            model_name='realm',
            old_name='config',
            new_name='backend_kwargs',
        ),
        migrations.RunPython(encrypt_realm_secrets),
    ]
