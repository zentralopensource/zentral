# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='LastReport',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('machine_serial_number', models.CharField(max_length=64, unique=True)),
                ('munki_version', models.CharField(max_length=32, null=True, blank=True)),
                ('user_agent', models.CharField(max_length=64)),
                ('ip', models.GenericIPAddressField(null=True, blank=True)),
                ('sha1sum', models.CharField(max_length=40)),
                ('run_type', models.CharField(max_length=64)),
                ('start_time', models.DateTimeField()),
                ('end_time', models.DateTimeField()),
                ('last_seen', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
