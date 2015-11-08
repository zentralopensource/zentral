# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osquery', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='distributedquerynode',
            name='result',
            field=models.TextField(blank=True, null=True),
        ),
    ]
