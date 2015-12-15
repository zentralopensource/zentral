# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0002_auto_20151215_1330'),
    ]

    operations = [
        migrations.AlterField(
            model_name='osxapp',
            name='bundle_name',
            field=models.TextField(null=True, db_index=True, blank=True),
        ),
        migrations.AlterField(
            model_name='osxapp',
            name='version',
            field=models.TextField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='osxapp',
            name='version_str',
            field=models.TextField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='osxappinstance',
            name='bundle_path',
            field=models.TextField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='osxappinstance',
            name='path',
            field=models.TextField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='osxappinstance',
            name='sha1',
            field=models.CharField(null=True, max_length=40, blank=True),
        ),
        migrations.AlterField(
            model_name='osxappinstance',
            name='sha256',
            field=models.CharField(null=True, db_index=True, max_length=64, blank=True),
        ),
        migrations.AlterField(
            model_name='osxappinstance',
            name='type',
            field=models.TextField(null=True, blank=True),
        ),
    ]
