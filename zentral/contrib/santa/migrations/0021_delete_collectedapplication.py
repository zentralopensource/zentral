# Generated by Django 2.2.17 on 2021-01-21 16:16

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0052_auto_20210122_1239'),
        ('santa', '0020_auto_20210119_1649'),
    ]

    operations = [
        migrations.DeleteModel(
            name='CollectedApplication',
        ),
    ]
