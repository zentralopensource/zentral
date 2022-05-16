# Generated by Django 3.2.12 on 2022-05-06 09:14

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('santa', '0027_auto_20220207_2112'),
    ]

    operations = [
        migrations.AddField(
            model_name='configuration',
            name='enable_all_event_upload_shard',
            field=models.IntegerField(
                default=0,
                help_text='Restrict the upload of all execution events to Zentral, '
                          'including those that were explicitly allowed, to a percentage (0-100) of hosts',
                validators=[django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(100)]
            ),
        ),
    ]