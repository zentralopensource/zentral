import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0113_enrolleddevice_filevault_and_software_update_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceStatusReport',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('received_at', models.DateTimeField()),
                ('full_report', models.BooleanField()),
                ('latest_full_report', models.BooleanField(default=False)),
                ('data', models.JSONField()),
                ('enrolled_device', models.ForeignKey(db_index=False,
                                                      on_delete=django.db.models.deletion.CASCADE,
                                                      related_name='status_reports',
                                                      to='mdm.enrolleddevice')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['enrolled_device', 'id'], name='mdm_devicestatusreport_tgt'),
                    models.Index(condition=models.Q(('full_report', True)),
                                 fields=['enrolled_device', 'id'],
                                 include=('received_at',),
                                 name='mdm_devicestatusreport_full'),
                ],
                'constraints': [
                    models.UniqueConstraint(condition=models.Q(('latest_full_report', True)),
                                            fields=('enrolled_device',),
                                            name='mdm_devicestatusreport_latest_full_report'),
                ],
            },
        ),
        migrations.CreateModel(
            name='UserStatusReport',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('received_at', models.DateTimeField()),
                ('full_report', models.BooleanField()),
                ('latest_full_report', models.BooleanField(default=False)),
                ('data', models.JSONField()),
                ('enrolled_user', models.ForeignKey(db_index=False,
                                                    on_delete=django.db.models.deletion.CASCADE,
                                                    related_name='status_reports',
                                                    to='mdm.enrolleduser')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['enrolled_user', 'id'], name='mdm_userstatusreport_tgt'),
                    models.Index(condition=models.Q(('full_report', True)),
                                 fields=['enrolled_user', 'id'],
                                 include=('received_at',),
                                 name='mdm_userstatusreport_full'),
                ],
                'constraints': [
                    models.UniqueConstraint(condition=models.Q(('latest_full_report', True)),
                                            fields=('enrolled_user',),
                                            name='mdm_userstatusreport_latest_full_report'),
                ],
            },
        ),
    ]
