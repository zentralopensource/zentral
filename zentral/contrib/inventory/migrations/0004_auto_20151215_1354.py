# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0003_auto_20151215_1352'),
    ]

    operations = [
        migrations.AlterField(
            model_name='osxapp',
            name='bundle_id',
            field=models.TextField(db_index=True, blank=True, null=True),
        ),
    ]
