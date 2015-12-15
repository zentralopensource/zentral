# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0004_auto_20151215_1354'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='machinesnapshot',
            name='next_snapshot',
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='mt_next',
            field=models.OneToOneField(related_name='mt_previous', blank=True, null=True, to='inventory.MachineSnapshot'),
        ),
    ]
