# Generated by Django 4.2.18 on 2025-02-09 13:11

from django.db import migrations, models


def set_default_counters(apps, schema_editor):
    DeviceArtifact = apps.get_model("mdm", "DeviceArtifact")
    DeviceArtifact.objects.filter(installed_at__isnull=False).update(install_count=1)
    UserArtifact = apps.get_model("mdm", "UserArtifact")
    UserArtifact.objects.filter(installed_at__isnull=False).update(install_count=1)


class Migration(migrations.Migration):

    dependencies = [
        ("mdm", "0084_declaration_alter_artifact_type_dataasset_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="deviceartifact",
            name="install_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="deviceartifact",
            name="max_retry_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="deviceartifact",
            name="retry_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="userartifact",
            name="install_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="userartifact",
            name="max_retry_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="userartifact",
            name="retry_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="deviceartifact",
            name="status",
            field=models.CharField(
                choices=[
                    ("Acknowledged", "Acknowledged"),
                    ("AwaitingConfirmation", "Awaiting Confirmation"),
                    ("Installed", "Installed"),
                    ("Uninstalled", "Uninstalled"),
                    ("Failed", "Failed"),
                    ("RemovalFailed", "Removal Failed"),
                    ("ForceReinstall", "Force Reinstall"),
                ],
                default="Acknowledged",
                max_length=64,
            ),
        ),
        migrations.AlterField(
            model_name="userartifact",
            name="status",
            field=models.CharField(
                choices=[
                    ("Acknowledged", "Acknowledged"),
                    ("AwaitingConfirmation", "Awaiting Confirmation"),
                    ("Installed", "Installed"),
                    ("Uninstalled", "Uninstalled"),
                    ("Failed", "Failed"),
                    ("RemovalFailed", "Removal Failed"),
                    ("ForceReinstall", "Force Reinstall"),
                ],
                default="Acknowledged",
                max_length=64,
            ),
        ),
        migrations.RunPython(set_default_counters),
    ]
