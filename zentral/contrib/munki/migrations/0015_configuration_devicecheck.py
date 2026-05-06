from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('munki', '0014_munkistate_force_full_sync_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='configuration',
            name='devicecheck_private_key',
            field=models.TextField(blank=True, default='', editable=False),
        ),
        migrations.AddField(
            model_name='configuration',
            name='devicecheck_private_key_id',
            field=models.CharField(blank=True, max_length=10),
        ),
        migrations.AddField(
            model_name='configuration',
            name='devicecheck_team_id',
            field=models.CharField(blank=True, max_length=10),
        ),
        migrations.AddField(
            model_name='configuration',
            name='devicecheck_sandbox',
            field=models.BooleanField(default=False),
        ),
    ]
