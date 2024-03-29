# -*- coding: utf-8 -*-
# Generated by Django 1.10.7 on 2017-09-19 09:32
from __future__ import unicode_literals

import django.contrib.postgres.fields
from django.db import migrations, models
import django.db.models.deletion
import zentral.contrib.monolith.models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0025_machinesnapshotcommit_system_uptime'),
        ('monolith', '0024_auto_20170818_1222'),
    ]

    operations = [
        migrations.CreateModel(
            name='Printer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128)),
                ('info', models.CharField(blank=True, help_text='description of the printer', max_length=256)),
                ('location', models.CharField(blank=True, help_text='location of the printer', max_length=256)),
                ('scheme', models.CharField(choices=[('ipp', 'ipp'), ('ipps', 'ipps'), ('http', 'http'), ('https', 'https')], default='ipp', max_length=5)),
                ('address', models.CharField(max_length=256)),
                ('shared', models.BooleanField(default=False)),
                ('error_policy', models.CharField(choices=[('abort-job', 'Abort job'), ('retry-job', 'Retry job'), ('retry-current-job', 'Retry current job'), ('stop-printer', 'Stop printer')], default='abort-job', max_length=32)),
                ('version', models.PositiveSmallIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('manifest', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='monolith.Manifest')),
            ],
        ),
        migrations.CreateModel(
            name='PrinterPPD',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('model_name', models.CharField(editable=False, max_length=256)),
                ('short_nick_name', models.CharField(editable=False, max_length=256)),
                ('manufacturer', models.CharField(editable=False, max_length=256)),
                ('product', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=256), editable=False, size=None)),
                ('file_version', models.CharField(editable=False, max_length=256)),
                ('pc_file_name', models.CharField(editable=False, max_length=12)),
                ('file', models.FileField(upload_to="legacy_path")),
                ('file_compressed', models.BooleanField(editable=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddField(
            model_name='printer',
            name='ppd',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='monolith.PrinterPPD'),
        ),
        migrations.AddField(
            model_name='printer',
            name='tags',
            field=models.ManyToManyField(to='inventory.Tag'),
        ),
    ]
