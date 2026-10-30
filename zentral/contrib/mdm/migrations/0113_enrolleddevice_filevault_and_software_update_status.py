from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0112_enrolleddevice_software_update_device_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='enrolleddevice',
            name='filevault_enabled',
            field=models.BooleanField(null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_install_state',
            field=models.CharField(max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_pending_os_version',
            field=models.CharField(max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_pending_build_version',
            field=models.CharField(max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_failure_count',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_failure_reason',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='enrolleddevice',
            name='software_update_failure_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.RunSQL(
            "UPDATE mdm_enrolleddevice "
            "SET filevault_enabled = (security_info->>'FDE_Enabled')::boolean "
            "WHERE jsonb_typeof(security_info->'FDE_Enabled') = 'boolean'",
            migrations.RunSQL.noop,
        ),
    ]
