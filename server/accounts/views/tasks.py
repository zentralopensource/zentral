import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView

from accounts.models import task_results_for_user
from zentral.utils.views import UserPaginationListView

logger = logging.getLogger("zentral.accounts.views.tasks")


class TaskViewMixin:
    def get_queryset(self):
        return (task_results_for_user(self.request.user)
                .select_related('usertask')
                .order_by('-date_created'))


class TasksView(LoginRequiredMixin, TaskViewMixin, UserPaginationListView):
    template_name = "accounts/task_list.html"


class TaskView(LoginRequiredMixin, TaskViewMixin, DetailView):
    template_name = "accounts/task_detail.html"

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, task_id=self.kwargs["task_id"])
