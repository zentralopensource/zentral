import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='WatchState',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('watch', models.CharField(max_length=256)),
                ('subject_id', models.TextField()),
                ('serial_number', models.TextField(db_index=True, null=True)),
                ('reasons', django.contrib.postgres.fields.ArrayField(
                    base_field=models.CharField(max_length=256), size=None)),
                ('previous_reasons', django.contrib.postgres.fields.ArrayField(
                    base_field=models.CharField(max_length=256), default=list, size=None)),
                ('severity', models.PositiveSmallIntegerField(null=True)),
                ('incident_key', models.JSONField(null=True)),
                ('first_fired_at', models.DateTimeField()),
                ('fired_at', models.DateTimeField()),
            ],
            options={
                'constraints': [
                    models.UniqueConstraint(fields=('watch', 'subject_id'),
                                            name='watchers_watchstate_unique')
                ],
            },
        ),
    ]
