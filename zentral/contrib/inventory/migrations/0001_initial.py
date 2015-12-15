# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BusinessUnit',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('name', models.TextField()),
                ('reference', models.TextField(unique=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('common_name', models.TextField()),
                ('organization', models.TextField()),
                ('organizational_unit', models.TextField()),
                ('sha1', models.CharField(max_length=40)),
                ('sha256', models.CharField(db_index=True, max_length=64)),
                ('valid_from', models.DateTimeField()),
                ('valid_until', models.DateTimeField()),
                ('signed_by', models.ForeignKey(null=True, to='inventory.Certificate', blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Machine',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('serial_number', models.TextField(unique=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='MachineGroup',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('name', models.TextField()),
                ('reference', models.TextField(unique=True)),
                ('business_unit', models.ForeignKey(null=True, to='inventory.BusinessUnit', blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='MachineSnapshot',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('source', models.TextField(db_index=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('groups', models.ManyToManyField(to='inventory.MachineGroup')),
                ('machine', models.ForeignKey(to='inventory.Machine')),
                ('next_snapshot', models.ForeignKey(null=True, to='inventory.MachineSnapshot', blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OSVersion',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('name', models.TextField()),
                ('major', models.PositiveIntegerField()),
                ('minor', models.PositiveIntegerField()),
                ('patch', models.PositiveIntegerField(null=True, blank=True)),
                ('build', models.TextField(null=True, blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OSXApp',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('bundle_id', models.TextField(db_index=True)),
                ('bundle_name', models.TextField(db_index=True)),
                ('version', models.TextField()),
                ('version_str', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OSXAppInstance',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('bundle_path', models.TextField()),
                ('path', models.TextField()),
                ('sha1', models.CharField(max_length=40)),
                ('sha256', models.CharField(db_index=True, max_length=64)),
                ('type', models.TextField()),
                ('app', models.ForeignKey(to='inventory.OSXApp')),
                ('signed_by', models.ForeignKey(null=True, to='inventory.Certificate', blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SystemInfo',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('mt_hash', models.CharField(unique=True, max_length=40)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('computer_name', models.TextField()),
                ('hostname', models.TextField(null=True, blank=True)),
                ('hardware_model', models.TextField(null=True, blank=True)),
                ('hardware_serial', models.TextField(null=True, blank=True)),
                ('cpu_type', models.TextField(null=True, blank=True)),
                ('cpu_subtype', models.TextField(null=True, blank=True)),
                ('cpu_brand', models.TextField(null=True, blank=True)),
                ('cpu_physical_cores', models.PositiveIntegerField(null=True, blank=True)),
                ('cpu_logical_cores', models.PositiveIntegerField(null=True, blank=True)),
                ('physical_memory', models.BigIntegerField()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='os_version',
            field=models.ForeignKey(null=True, to='inventory.OSVersion', blank=True),
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='osx_app_instances',
            field=models.ManyToManyField(to='inventory.OSXAppInstance'),
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='system_info',
            field=models.ForeignKey(null=True, to='inventory.SystemInfo', blank=True),
        ),
        migrations.RemoveField(
            model_name='machinesnapshot',
            name='created_at',
        ),
        migrations.RemoveField(
            model_name='osxapp',
            name='created_at',
        ),
    ]
