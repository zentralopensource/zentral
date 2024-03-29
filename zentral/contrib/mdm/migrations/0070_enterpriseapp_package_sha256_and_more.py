# Generated by Django 4.1.9 on 2023-09-17 11:48
import hashlib
from django.db import migrations, models


def update_package_sha256_and_size(apps, schema_editor):
    EnterpriseApp = apps.get_model("mdm", "EnterpriseApp")
    for app in EnterpriseApp.objects.all():
        h = hashlib.sha256()
        size = 0
        for chunk in app.package.chunks():
            h.update(chunk)
            size += len(chunk)
        app.package_sha256 = h.hexdigest()
        app.package_size = size
        app.save()


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0069_enrolleddevice_pending_firmware_password_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='enterpriseapp',
            name='package_sha256',
            field=models.CharField(default='', max_length=64),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='enterpriseapp',
            name='package_size',
            field=models.BigIntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='enterpriseapp',
            name='package_uri',
            field=models.TextField(default=''),
        ),
        migrations.RunPython(update_package_sha256_and_size),
    ]
