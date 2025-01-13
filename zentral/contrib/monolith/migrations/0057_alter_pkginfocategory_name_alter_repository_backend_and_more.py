# Generated by Django 4.2.17 on 2025-01-13 19:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monolith', '0056_repository_provisioning_uid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pkginfocategory',
            name='name',
            field=models.CharField(max_length=256),
        ),
        migrations.AlterField(
            model_name='repository',
            name='backend',
            field=models.CharField(choices=[('AZURE', 'Azure Blob Storage'),
                                            ('S3', 'Amazon S3'),
                                            ('VIRTUAL', 'Virtual')],
                                   max_length=32),
        ),
        migrations.AlterUniqueTogether(
            name='pkginfo',
            unique_together={('repository', 'name', 'version')},
        ),
    ]