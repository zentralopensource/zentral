# Generated by Django 2.2.24 on 2021-06-08 16:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0043_enterpriseapp_bundles'),
    ]

    operations = [
        migrations.AddField(
            model_name='enrolleddevice',
            name='declarative_management',
            field=models.BooleanField(default=False),
        ),
    ]
