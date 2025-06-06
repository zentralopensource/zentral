# Generated by Django 4.2.18 on 2025-04-17 16:56

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("mdm", "0088_alter_depdevice_options_depdevice_disowned_at"),
    ]

    operations = [
        migrations.CreateModel(
            name="EnrollmentCustomView",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(unique=True)),
                ("description", models.TextField(blank=True)),
                ("html", models.TextField(verbose_name="HTML template")),
                ("requires_authentication", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="DEPEnrollmentCustomView",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("weight", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "custom_view",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="mdm.enrollmentcustomview",
                    ),
                ),
                (
                    "dep_enrollment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="mdm.depenrollment",
                    ),
                ),
            ],
            options={
                "unique_together": {
                    ("dep_enrollment", "weight"),
                    ("dep_enrollment", "custom_view"),
                },
            },
        ),
    ]
