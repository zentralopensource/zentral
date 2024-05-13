# Generated by Django 4.2.11 on 2024-05-10 14:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0076_depenrollment_username_pattern_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scepconfig',
            name='challenge_type',
            field=models.CharField(choices=[('STATIC', 'Static'),
                                            ('MICROSOFT_CA', 'Microsoft CA Web Enrollment (certsrv)'),
                                            ('OKTA_CA', 'Okta CA Dynamic Challenge')],
                                   max_length=64),
        ),
    ]