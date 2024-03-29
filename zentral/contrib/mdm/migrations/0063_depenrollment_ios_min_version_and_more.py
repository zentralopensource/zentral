# Generated by Django 4.1.9 on 2023-06-20 09:00

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0062_enrolleddevice_blocked_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='depenrollment',
            name='ios_min_version',
            field=models.CharField(blank=True, max_length=32, verbose_name='Required iOS version'),
        ),
        migrations.AddField(
            model_name='depenrollment',
            name='macos_min_version',
            field=models.CharField(blank=True, max_length=32, verbose_name='Required macOS version'),
        ),
        migrations.AlterField(
            model_name='depenrollment',
            name='skip_setup_items',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=64), editable=False, size=None),
        ),
    ]
