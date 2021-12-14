# Generated by Django 2.2.24 on 2021-12-14 14:33

from django.db import migrations, models


def set_incident_name(apps, schema_editor):
    Incident = apps.get_model("incidents", "Incident")
    try:
        from zentral.core.incidents import incident_types
    except Exception:
        return
    for incident in Incident.objects.all():
        incident_cls = incident_types.get(incident.incident_type)
        if not incident_cls:
            incident_cls = incident_types.get("base")
        incident.name = incident_cls(incident).get_name()
        incident.save()


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0002_auto_20211201_1224'),
    ]

    operations = [
        migrations.AddField(
            model_name='incident',
            name='name',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
        migrations.RunPython(set_incident_name),
    ]