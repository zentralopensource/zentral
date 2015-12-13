# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('munki', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='MunkiState',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('machine_serial_number', models.CharField(unique=True, max_length=64)),
                ('munki_version', models.CharField(blank=True, null=True, max_length=32)),
                ('user_agent', models.CharField(max_length=64)),
                ('ip', models.GenericIPAddressField(blank=True, null=True)),
                ('sha1sum', models.CharField(max_length=40)),
                ('run_type', models.CharField(max_length=64)),
                ('start_time', models.DateTimeField()),
                ('end_time', models.DateTimeField()),
                ('binaryinfo_last_seen', models.DateTimeField(blank=True, null=True)),
                ('last_seen', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.DeleteModel(
            name='LastReport',
        ),
    ]
