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
    _, extension = os.path.splitext(filename)
    with open(filepath, "wb") as of:
        if extension == ".zip":
            content_type = "application/zip"
            msquery.export_zip(of)
        elif extension == ".xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            msquery.export_xlsx(of)
        else:
            raise ValueError("Unknown file extension '{}'".format(extension))
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": content_type,
            "Content-Disposition": 'attachment; filename="{}"'.format(filename.replace('"', "'")),
        }
    }
