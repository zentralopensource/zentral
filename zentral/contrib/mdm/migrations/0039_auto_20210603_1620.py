# Generated by Django 2.2.24 on 2021-06-03 16:20

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0038_auto_20210601_1838'),
    ]

    operations = [
        migrations.CreateModel(
            name='SCEPConfig',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=256, unique=True)),
                ('url', models.URLField()),
                ('challenge_type', models.CharField(choices=[('STATIC', 'Static'), ('MICROSOFT_CA', 'Microsoft CA Web Enrollment (certsrv)')], max_length=64)),
                ('challenge_kwargs', django.contrib.postgres.fields.jsonb.JSONField(editable=False)),
                ('key_usage', models.IntegerField(choices=[(0, 'None (0)'), (1, 'Signing (1)'), (4, 'Encryption (4)'), (5, 'Signing & Encryption (1 | 4 = 5)')], default=0, help_text='A bitmask indicating the use of the key.')),
                ('key_is_extractable', models.BooleanField(default=False, help_text='If true, the private key can be exported from the keychain.')),
                ('keysize', models.IntegerField(choices=[(1024, '1024-bit'), (2048, '2048-bit'), (4096, '4096-bit')], default=2048)),
                ('allow_all_apps_access', models.BooleanField(default=False, help_text='If true, all apps have access to the private key.')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AlterModelOptions(
            name='blueprint',
            options={'ordering': ('name', 'created_at')},
        ),
        migrations.AlterField(
            model_name='enrolleddevice',
            name='blueprint',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='mdm.Blueprint'),
        ),
    ]
