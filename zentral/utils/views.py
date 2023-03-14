from django.db import transaction
from django.views.generic import CreateView, DeleteView, UpdateView
from zentral.core.events.base import AuditEvent


class CreateViewWithAudit(CreateView):
    def form_valid(self, form):
        response = super().form_valid(form)
        event = AuditEvent.build_from_request_and_instance(
            self.request, self.object,
            action="created",
            new_value=self.object.serialize_for_event(),
        )
        transaction.on_commit(lambda: event.post())
        return response


class UpdateViewWithAudit(UpdateView):
    def form_valid(self, form):
        obj = self.get_object()  # self.object is already updated
        prev_value = obj.serialize_for_event()
        response = super().form_valid(form)
        event = AuditEvent.build_from_request_and_instance(
            self.request, obj,
            action="updated",
            prev_value=prev_value,
            new_value=self.object.serialize_for_event(),
        )
        transaction.on_commit(lambda: event.post())
        return response


class DeleteViewWithAudit(DeleteView):
    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        event = AuditEvent.build_from_request_and_instance(
            self.request, self.object,
            action="deleted",
            prev_value=self.object.serialize_for_event()
        )
        transaction.on_commit(lambda: event.post())
        return super().delete(request, *args, **kwargs)
