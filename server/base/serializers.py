import logging

from django.urls import reverse
from rest_framework import serializers

logger = logging.getLogger("server.base.serializers")


class TaskSerializer(serializers.Serializer):
    task_id = serializers.UUIDField(required=True)
    task_result_url = serializers.CharField(min_length=None, allow_blank=False)

    @classmethod
    def from_task(cls, task):
        return cls(
            data={
                "task_id": str(task.id),
                "task_result_url": reverse("base_api:task_result", args=(task.id,)),
            }
        )
