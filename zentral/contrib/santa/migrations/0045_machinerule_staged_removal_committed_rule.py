from django.db import migrations
from django.db.models import F


def capture_the_committed_rules_of_the_staged_removals(apps, schema_editor):
    # a staged removal now keeps the rule the client holds in the committed policy and version,
    # and a staged removal without them covers a rule staged during the same session, which is
    # dropped when the session is discarded. The removals staged by the previous version never
    # captured the committed rule: mark them all as covering a rule the client holds, like the
    # previous version assumed, so that an in-flight session crossing the upgrade cannot lose one.
    MachineRule = apps.get_model("santa", "MachineRule")
    (MachineRule.objects.filter(staged_removal=True, committed_policy__isnull=True)
                        .update(committed_policy=F("policy"), committed_version=F("version")))


class Migration(migrations.Migration):

    dependencies = [
        ('santa', '0044_machinerule_committed_policy_and_more'),
    ]

    operations = [
        migrations.RunPython(capture_the_committed_rules_of_the_staged_removals,
                             migrations.RunPython.noop),
    ]
