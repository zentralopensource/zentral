from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0111_softwareupdateenforcement_device_os_version'),
    ]

    operations = [
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_device_id',
            field=models.TextField(null=True),
        ),
        migrations.RunSQL(
            "UPDATE mdm_enrolleddevice "
            "SET software_update_device_id = device_information->>'SoftwareUpdateDeviceID' "
            "WHERE jsonb_typeof(device_information->'SoftwareUpdateDeviceID') = 'string' "
            "AND device_information->>'SoftwareUpdateDeviceID' <> ''",
            migrations.RunSQL.noop,
        ),
    ]
