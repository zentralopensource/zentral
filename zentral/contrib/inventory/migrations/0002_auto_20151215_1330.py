# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='machinegroup',
            name='business_unit',
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='business_unit',
            field=models.ForeignKey(blank=True, null=True, to='inventory.BusinessUnit'),
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='reference',
            field=models.TextField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='businessunit',
            name='reference',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='machinegroup',
            name='reference',
            field=models.TextField(),
        ),
    ]
