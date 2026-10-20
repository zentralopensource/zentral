import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("turbo", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="job",
            name="kind",
            field=models.CharField(
                choices=[
                    ("script", "Script"),
                    ("mscp_check", "mSCP check"),
                    ("sysdiagnose", "Sysdiagnose"),
                    ("file_export", "File export"),
                ],
                editable=False,
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="Command",
            fields=[
                ("name", models.CharField()),
                ("description", models.TextField(blank=True)),
                ("backend_kwargs", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "id",
                    models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
                ),
                (
                    "backend",
                    models.CharField(
                        choices=[("sysdiagnose", "Sysdiagnose"), ("file_export", "File export")]
                    ),
                ),
                (
                    "job",
                    models.OneToOneField(
                        editable=False,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="command",
                        to="turbo.job",
                    ),
                ),
            ],
            options={
                "default_permissions": (),
                "constraints": [
                    models.UniqueConstraint(fields=("backend", "name"), name="turbo_command_backend_name_unique")
                ],
            },
        ),
        migrations.CreateModel(
            name="FileExport",
            fields=[],
            options={
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("turbo.command",),
        ),
        migrations.CreateModel(
            name="Sysdiagnose",
            fields=[],
            options={
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("turbo.command",),
        ),
    ]
