import os
from celery import shared_task
from django.conf import settings
from django.http import QueryDict
from .utils import MSQuery


@shared_task
def export_inventory(urlencoded_query_dict, filename):
    msquery = MSQuery(QueryDict(urlencoded_query_dict))
    export_dir = os.path.join(settings.MEDIA_ROOT, "exports")
    if not os.path.isdir(export_dir):
        os.makedirs(export_dir)
    filepath = os.path.join(export_dir, filename)
    with open(filepath, "wb") as of:
        msquery.export_xlsx(of)
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "Content-Disposition": 'attachment; filename="{}"'.format(filename.replace('"', "'")),
        }
    }
