from django.db import transaction
from django.views.generic import CreateView, DeleteView, ListView, UpdateView
from zentral.core.events.base import AuditEvent


class UserPaginationMixin:
    def get_paginate_by(self, queryset=None):
        return self.request.user.items_per_page


class UserPaginationListView(UserPaginationMixin, ListView):
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        page = ctx['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        return ctx


class CreateViewWithAudit(CreateView):
    def form_valid(self, form):
        response = super().form_valid(form)

        def post_event():
            event = AuditEvent.build_from_request_and_instance(
                self.request, self.object,
                action=AuditEvent.Action.CREATED,
            )
            event.post()

        transaction.on_commit(lambda: post_event())
        return response


class UpdateViewWithAudit(UpdateView):
    def form_valid(self, form):
        obj = self.get_object()  # self.object is already updated
        prev_value = obj.serialize_for_event()
        response = super().form_valid(form)

        def post_event():
            event = AuditEvent.build_from_request_and_instance(
                self.request, self.object,
                action=AuditEvent.Action.UPDATED,
                prev_value=prev_value
            )
            event.post()

        transaction.on_commit(lambda: post_event())
        return response


class DeleteViewWithAudit(DeleteView):
    def form_valid(self, form):
        self.object = self.get_object()
        # build the event before the object is deleted
        event = AuditEvent.build_from_request_and_instance(
            self.request, self.object,
            action=AuditEvent.Action.DELETED,
            prev_value=self.object.serialize_for_event()
        )
        transaction.on_commit(lambda: event.post())
        return super().form_valid(form)
