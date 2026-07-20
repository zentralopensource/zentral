from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("mdm", "0105_packageref"),
    ]

    operations = [
        migrations.AddField(
            model_name="enrolleddevice",
            name="declaration_items_snapshot",
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name="enrolleduser",
            name="declaration_items_snapshot",
            field=models.JSONField(default=dict),
        ),
    ]
