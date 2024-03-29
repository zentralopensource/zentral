# Generated by Django 2.2.24 on 2021-12-10 09:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0058_machine_snapshot_disks_on_delete_cascade'),
    ]

    operations = [
        migrations.CreateModel(
            name='Payload',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('mt_hash', models.CharField(max_length=40, unique=True)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('uuid', models.TextField()),
                ('identifier', models.TextField(blank=True, null=True)),
                ('display_name', models.TextField(blank=True, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('type', models.TextField(blank=True, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('mt_hash', models.CharField(max_length=40, unique=True)),
                ('mt_created_at', models.DateTimeField(auto_now_add=True)),
                ('uuid', models.TextField(db_index=True)),
                ('identifier', models.TextField(blank=True, null=True)),
                ('display_name', models.TextField(blank=True, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('organization', models.TextField(blank=True, null=True)),
                ('removal_disallowed', models.BooleanField(blank=True, null=True)),
                ('verified', models.BooleanField(blank=True, null=True)),
                ('install_date', models.DateTimeField(blank=True, null=True)),
                ('payloads', models.ManyToManyField(to='inventory.Payload')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='machinesnapshot',
            name='profiles',
            field=models.ManyToManyField(to='inventory.Profile'),
        ),
    ]
