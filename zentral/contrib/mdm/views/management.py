import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import DetailView, TemplateView, View
from zentral.contrib.mdm.apns import send_device_notification
from zentral.contrib.mdm.forms import EnrolledDeviceSearchForm
from zentral.contrib.mdm.models import EnrolledDevice

logger = logging.getLogger('zentral.contrib.mdm.views.management')


class EnrolledDevicesView(LoginRequiredMixin, TemplateView):
    template_name = "mdm/enrolleddevice_list.html"

    def get(self, request, *args, **kwargs):
        self.form = EnrolledDeviceSearchForm(request.GET)
        self.form.is_valid()
        self.search_qs = self.form.search_qs()
        self.search_count = self.search_qs.count()
        if self.search_count == 1:
            return HttpResponseRedirect(reverse("mdm:enrolled_device", args=(self.search_qs[0].pk,)))
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["mdm"] = True
        ctx["form"] = self.form
        ctx["enrolled_devices"] = self.search_qs
        ctx["enrolled_devices_count"] = self.search_count
        if not self.form.is_initial():
            bc = [(reverse("mdm:enrolled_devices"), "Enrolled devices"),
                  (None, "Search")]
        else:
            bc = [(None, "Enrolled devices")]
        ctx["breadcrumbs"] = bc
        return ctx


class EnrolledDeviceView(LoginRequiredMixin, DetailView):
    model = EnrolledDevice


class PokeEnrolledDeviceView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        send_device_notification(enrolled_device)
        messages.info(request, "Device poked!")
        return HttpResponseRedirect(reverse("mdm:enrolled_device", args=(enrolled_device.id,)))
