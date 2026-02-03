from functools import reduce
import operator
from abc import ABC, abstractmethod
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
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
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self._get_group().permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self._get_group().permissions.clear()

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
