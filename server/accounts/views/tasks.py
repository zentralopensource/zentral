import logging
from django.contrib.auth.mixins import LoginRequiredMixin

from django_celery_results.models import TaskResult
from django.views.generic import DetailView
from zentral.utils.views import UserPaginationListView
from django.shortcuts import get_object_or_404

logger = logging.getLogger("zentral.accounts.views.tasks")


class TaskViewMixin:
    def get_queryset(self):
        queryset = TaskResult.objects.select_related('usertask').all()
        if not self.request.user.is_superuser:
            queryset = queryset.filter(usertask__user=self.request.user)
        return queryset.order_by('-date_created')


class TasksView(LoginRequiredMixin, TaskViewMixin, UserPaginationListView):
    template_name = "accounts/task_list.html"


class TaskView(LoginRequiredMixin, TaskViewMixin, DetailView):
    template_name = "accounts/task_detail.html"

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, task_id=self.kwargs["task_id"])
