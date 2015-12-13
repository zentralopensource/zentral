# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('munki', '0002_auto_20151213_1321'),
    ]

    operations = [
        migrations.AlterField(
            model_name='munkistate',
            name='end_time',
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='munkistate',
            name='run_type',
            field=models.CharField(null=True, max_length=64, blank=True),
        ),
        migrations.AlterField(
            model_name='munkistate',
            name='sha1sum',
            field=models.CharField(null=True, max_length=40, blank=True),
        ),
        migrations.AlterField(
            model_name='munkistate',
            name='start_time',
            field=models.DateTimeField(null=True, blank=True),
        ),
    ]
