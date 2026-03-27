from abc import ABC, abstractmethod
from accounts.models import Policy
from accounts.pbac.engine import engine
from accounts.pbac.entities import Principal
from django.contrib.auth.models import Group
from django.http import QueryDict
from django.urls import reverse
from accounts.models import User


class LoginCase(ABC):
    @abstractmethod
    def _get_group(self) -> Group:
        pass

    @abstractmethod
    def _get_user(self) -> User:
        pass

    @abstractmethod
    def _get_url_namespace(self) -> str:
        pass

    def set_permissions(self, *permissions):
        if permissions:
            principal = str(Principal.from_user(self._get_user()))
            actions = [
                engine.legacy_perm_actions[permission]
                for permission in permissions
            ]
            actions.extend(
                engine.module_legacy_perm_actions[app_label]
                for app_label in set(p.split(".")[0] for p in permissions)
            )
            serialized_actions = ", ".join(str(a) for a in actions)
            policy = (
                'permit (\n'
                f'  principal == {principal},\n'
                f'  action in [{serialized_actions}],\n'
                '  resource\n'
                ');'
            )
            Policy.objects.update_or_create(
                name="Tests",
                defaults={"source": policy}
            )
        else:
            Policy.objects.all().delete()

    def build_url(self, url_name, *args):
        url_namespace = self._get_url_namespace()
        return reverse(f"{url_namespace}:{url_name}", args=args)

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self._get_user())

    def login_redirect(self, url_name, *args, data=None):
        url = self.build_url(url_name, *args)
        if data:
            response = self.client.post(url, data=data, follow=True)
        else:
            response = self.client.get(url)
        params = QueryDict(mutable=True)
        params["next"] = url
        self.assertRedirects(response, reverse("login") + "?" + params.urlencode())

    def permission_denied(self, url_name, *args, data=None):
        url = self.build_url(url_name, *args)
        if data:
            response = self.client.post(url, data=data, follow=True)
        else:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
