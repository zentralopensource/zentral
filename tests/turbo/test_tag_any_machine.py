from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.zentral_test_utils.tag_any_machine_case import TagAnyMachineAPISaveCase, TagAnyMachineFormSaveCase
from zentral.contrib.turbo.models import Script

from .utils import TurboAPITestCase, TurboSetupTestCase, force_script


# The tag of a script: the machines get it when a result comes in.


class ScriptTagCase:
    tam_permissions = ("turbo.add_script", "turbo.change_script")
    tam_many = False
    tam_error_path = ("tag",)
    tam_field_name = "tag"

    def tam_force_object(self, tags):
        return force_script(tag=tags[0] if tags else None)

    def tam_saved_tags(self, response=None, obj=None):
        script = Script.objects.get(pk=obj.pk) if obj else Script.objects.get(name=self.name)
        return {script.tag} if script.tag else set()


class ScriptAPITestCase(ScriptTagCase, TagAnyMachineAPISaveCase, TurboAPITestCase):
    def payload(self, name, tags, omit_tags=False):
        payload = {"name": name, "source": "echo changed"}
        if not omit_tags:
            payload["tag"] = tags[0].pk if tags else None
        return payload

    def tam_create(self, tags):
        self.name = get_random_string(12)
        return self.post(reverse("turbo_api:scripts"), self.payload(self.name, tags))

    def tam_update(self, obj, tags, omit_tags=False):
        return self.put(reverse("turbo_api:script", args=(obj.pk,)), self.payload(obj.name, tags, omit_tags))


class ScriptFormTestCase(ScriptTagCase, TagAnyMachineFormSaveCase, TurboSetupTestCase):
    def data(self, name, tags):
        data = {"name": name, "source": "echo changed", "arch_amd64": "on", "arch_arm64": "on"}
        if tags:
            data["tag"] = tags[0].pk
        return data

    def tam_create(self, tags):
        self.client.force_login(self.user)
        self.name = get_random_string(12)
        return self.client.post(reverse("turbo:create_script"), self.data(self.name, tags))

    def tam_update(self, obj, tags, omit_tags=False):
        self.client.force_login(self.user)
        return self.client.post(reverse("turbo:update_script", args=(obj.pk,)), self.data(obj.name, tags))

    def tam_get_update_form(self, obj):
        self.client.force_login(self.user)
        return self.client.get(reverse("turbo:update_script", args=(obj.pk,)))
