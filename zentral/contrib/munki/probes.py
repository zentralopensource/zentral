from django.urls import reverse_lazy
from rest_framework import serializers
from zentral.core.probes import register_probe_class
from zentral.core.probes.base import BaseProbe, BaseProbeSerializer, PayloadFilter


class MunkiInstallProbeSerializer(BaseProbeSerializer):
    install_types = serializers.MultipleChoiceField(choices=("install", "removal"))
    installed_item_names = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    unattended_installs = serializers.BooleanField(required=False)


class MunkiInstallProbe(BaseProbe):
    serializer_class = MunkiInstallProbeSerializer
    model_display = "munki install"
    create_url = reverse_lazy("munki:create_install_probe")
    template_name = "munki/install_probe.html"
    forced_event_type = "munki_event"
    can_edit_payload_filters = False

    def load_validated_data(self, data):
        super().load_validated_data(data)
        self.install_types = data["install_types"]
        self.installed_item_names = data.get("installed_item_names", [])
        self.unattended_installs = data.get("unattended_installs")
        # probe with can_edit_payload_filters = False
        # override the payload filters
        payload_filter_data = [
            {"attribute": "type",
             "operator": PayloadFilter.IN,
             "values": self.install_types},
        ]
        if self.installed_item_names:
            payload_filter_data.append(
                {"attribute": "name",
                 "operator": PayloadFilter.IN,
                 "values": self.installed_item_names}
            )
        if self.unattended_installs is not None:
            payload_filter_data.append(
                {"attribute": "unattended",
                 "operator": PayloadFilter.IN,
                 "values": [str(self.unattended_installs)]}  # str comparison
            )
        self.payload_filters = [PayloadFilter(payload_filter_data)]

    def get_installed_item_names_display(self):
        return ", ".join(sorted(self.installed_item_names))

    def get_install_types_display(self):
        return ", ".join(sorted(self.install_types))


register_probe_class(MunkiInstallProbe)
