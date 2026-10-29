from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0110_deviceartifact_force_install_requested_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='softwareupdateenforcement',
            name='max_device_os_version',
            field=models.CharField(
                blank=True,
                help_text='Only the devices with an OS version lower than this version are enforced.',
                max_length=32,
                verbose_name='Maximum device OS version',
            ),
        ),
        migrations.AddField(
            model_name='softwareupdateenforcement',
            name='min_device_os_version',
            field=models.CharField(
                blank=True,
                help_text='Only the devices with an OS version greater than or equal to this version are enforced.',
                max_length=32,
                verbose_name='Minimum device OS version',
            ),
        ),
    ]
