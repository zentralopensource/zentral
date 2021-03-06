# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2018-05-15 17:49
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0037_auto_20180213_1407'),
        ('contenttypes', '0002_remove_content_type_name'),
        ('mdm', '0011_enrolleddevice_checkout_at'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceArtifactCommand',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('artifact_id', models.PositiveIntegerField()),
                ('artifact_version', models.PositiveIntegerField()),
                ('action', models.CharField(choices=[('INSTALL', 'Install'), ('REMOVE', 'Remove')], max_length=64)),
                ('command_time', models.DateTimeField()),
                ('result_time', models.DateTimeField(null=True)),
                ('status_code', models.CharField(choices=[('Acknowledged', 'Acknowledged'), ('Error', 'Error'), ('CommandFormatError', 'Command format error'), ('NotNow', 'Not now')], max_length=64, null=True)),
                ('artifact_content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.ContentType')),
                ('enrolled_device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mdm.EnrolledDevice')),
            ],
        ),
        migrations.CreateModel(
            name='KernelExtension',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(unique=True)),
                ('identifier', models.TextField(unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='KernelExtensionPolicy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identifier', models.UUIDField(default=uuid.uuid4, unique=True)),
                ('version', models.PositiveIntegerField(default=1)),
                ('allow_user_overrides', models.BooleanField(default=True, help_text='If set to true, users can approve additional kernel extensions not explicitly allowed by configuration profiles')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('trashed_at', models.DateTimeField(editable=False, null=True)),
                ('allowed_kernel_extensions', models.ManyToManyField(to='mdm.KernelExtension')),
            ],
        ),
        migrations.CreateModel(
            name='KernelExtensionTeam',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(unique=True)),
                ('identifier', models.CharField(max_length=10, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name='kernelextensionpolicy',
            name='allowed_teams',
            field=models.ManyToManyField(to='mdm.KernelExtensionTeam'),
        ),
        migrations.AddField(
            model_name='kernelextensionpolicy',
            name='meta_business_unit',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='kernel_extension_policy', to='inventory.MetaBusinessUnit'),
        ),
        migrations.AddField(
            model_name='kernelextension',
            name='team',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mdm.KernelExtensionTeam'),
        ),
    ]
