# from collections import OrderedDict
import logging
from django.contrib.auth.mixins import LoginRequiredMixin

from django_celery_results.models import TaskResult
from django.views.generic import DetailView
from zentral.utils.views import UserPaginationListView
from django.shortcuts import get_object_or_404, render


logger = logging.getLogger("zentral.accounts.views.tasks")


class TasksView(LoginRequiredMixin, UserPaginationListView):
    template_name = "accounts/task_list.html"

    def get_queryset(self):
        if self.request.user.is_superuser:
            return TaskResult.objects.all()
        else:
            return TaskResult.objects.select_related('tasks').filter(tasks__user_id=self.request.user.id)


class TaskView(LoginRequiredMixin, DetailView):

    def get(self, request, *args, **kwargs):
        task_result = get_object_or_404(TaskResult, task_id=str(kwargs["task_id"]))
        return render(request, "accounts/task_detail.html", context={"task": task_result})
