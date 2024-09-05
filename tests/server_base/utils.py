from datetime import datetime, timedelta
import json
import uuid
from django.utils.crypto import get_random_string
from django_celery_results.models import TaskResult


def force_task_result(bad_json=False, result=None):
    if result is None:
        result = {
            "filepath": f"exports/santa_targets_export_{get_random_string(12)}.xlsx",
            "headers": {
                "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "Content-Disposition": 'attachment; filename="santa_targets_export_2024-09-05_15-00-48.xlsx"',
            }
        }
    if bad_json:
        result_json = "{"
    else:
        result_json = json.dumps(result)
    tr = TaskResult.objects.create(
        task_id=str(uuid.uuid4()),
        task_name="zentral.contrib.santa.tasks.export_targets",
        task_args='"({}, \'xlsx\', \'santa_targets_export_2024-09-05_15-00-48.xlsx\')"',
        task_kwargs='"{}"',
        status='SUCCESS',
        worker="celery@000000000000",
        content_type='application/json',
        content_encoding='utf-8',
        result=result_json,
        date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
        date_done=datetime.utcnow() - timedelta(days=1),
        meta='{"children": []}'
    )
    filepath = result.pop("filepath", None)
    return tr, result, filepath
