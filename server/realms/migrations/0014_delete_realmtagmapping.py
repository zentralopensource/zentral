# Generated by Django 4.2.17 on 2025-01-07 09:17

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('realms', '0013_alter_realmgroupmapping_realm_group'),
    ]

    operations = [
        migrations.DeleteModel(
            name='RealmTagMapping',
        ),
    ]
