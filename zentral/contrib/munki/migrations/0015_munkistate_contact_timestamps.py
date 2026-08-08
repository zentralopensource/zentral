import django.utils.timezone
from django.db import migrations, models
from django.db.models import F


def backfill_timestamps(apps, schema_editor):
    # updated_at is the old last_seen: auto_now, so it moved on every save. In practice the only writer
    # was the postflight (force_full_sync is rare), so it is the best available approximation of the last
    # postflight. created_at follows it too, to keep created_at <= updated_at rather than "migration time".
    MunkiState = apps.get_model("munki", "MunkiState")
    MunkiState.objects.update(created_at=F("updated_at"), last_postflight_at=F("updated_at"))


class Migration(migrations.Migration):

    dependencies = [
        ('munki', '0014_munkistate_force_full_sync_at'),
    ]

    operations = [
        migrations.RenameField(
            model_name='munkistate',
            old_name='last_seen',
            new_name='updated_at',
        ),
        migrations.AddField(
            model_name='munkistate',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='munkistate',
            name='last_preflight_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='munkistate',
            name='last_postflight_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.RunPython(backfill_timestamps, migrations.RunPython.noop),
    ]
