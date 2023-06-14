from django.db import transaction
from django.views.generic import CreateView, DeleteView, UpdateView
from zentral.core.events.base import AuditEvent


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
