# Generated by Django 3.2.14 on 2022-08-11 10:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('santa', '0028_configuration_enable_all_event_upload_shard'),
    ]

    operations = [
        migrations.AddField(
            model_name='rule',
            name='description',
            field=models.TextField(blank=True),
        ),
    ]
