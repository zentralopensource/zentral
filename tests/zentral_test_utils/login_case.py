from abc import ABC, abstractmethod
from importlib import import_module
from typing import Optional

from cedarpy import format_policies
from django.conf import settings
from django.contrib.auth.models import Group
from django.http import HttpRequest, QueryDict
from django.urls import reverse
from django.utils.http import urlencode

from accounts.models import Policy
from accounts.pbac.engine import engine
from accounts.pbac.entities import Entity
from accounts.models import User
from realms.backends.views import finalize_session
from realms.models import Realm, RealmAuthenticationSession, RealmUser


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

    def _get_realm(self) -> Optional[Realm]:
        return

    def _get_realm_user(self) -> Optional[RealmUser]:
        return

    def set_policy(self, source):
        format_policies(source)
        Policy.objects.update_or_create(
            name="Tests",
            defaults={"source": source}
        )

    def set_permissions(self, *permissions):
        if permissions:
            serialized_role = str(Entity("Role", str(self._get_group().pk)))
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
                f'  principal in {serialized_role},\n'
                f'  action in [{serialized_actions}],\n'
                '  resource\n'
                ');'
            )
            self.set_policy(policy)
        else:
            Policy.objects.all().delete()

    def build_url(self, url_name, *args, query_params=None):
        url_namespace = self._get_url_namespace()
        url = reverse(f"{url_namespace}:{url_name}", args=args)
        if query_params:
            url = url + "?" + urlencode(query_params, doseq=True)
        return url

    def login(self, *permissions, realm_user=False):
        self.set_permissions(*permissions)
        if not realm_user:
            self.client.force_login(self._get_user())
        else:
            # see https://github.com/django/django/blob/705066d186ce880bf64142e47084f3d8df3c2352/django/test/client.py#L785  # NOQA
            request = HttpRequest()
            # HACK
            # see https://github.com/django/django/blob/705066d186ce880bf64142e47084f3d8df3c2352/django/contrib/auth/__init__.py#L141-L142  # NOQA
            # so that the user is attached to the request. The realm callback expects a user on the request!
            request.user = None
            if self.client.session:
                request.session = self.client.session
            else:
                session_engine = import_module(settings.SESSION_ENGINE)
                request.session = session_engine.SessionStore()
            ras = RealmAuthenticationSession.objects.create(
                realm=self._get_realm(),
                callback="realms.utils.login_callback",
            )
            finalize_session(ras, request, self._get_realm_user())
            request.session.save()
            session_cookie = settings.SESSION_COOKIE_NAME
            self.client.cookies[session_cookie] = request.session.session_key
            cookie_data = {
                "max-age": None,
                "path": "/",
                "domain": settings.SESSION_COOKIE_DOMAIN,
                "secure": settings.SESSION_COOKIE_SECURE or None,
                "expires": None,
            }
            self.client.cookies[session_cookie].update(cookie_data)

    def login_with_policy(self, policy):
        self.set_policy(policy)
        self.client.force_login(self._get_user())

    def login_redirect(self, url_name, *args, data=None, query_params=None):
        url = self.build_url(url_name, *args, query_params=query_params)
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
