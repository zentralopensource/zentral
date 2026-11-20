from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0114_status_reports'),
    ]

    operations = [
        migrations.DeleteModel(
            name='SCEPConfig',
        ),
    ]
