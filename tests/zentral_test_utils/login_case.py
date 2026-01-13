from functools import reduce
import operator
from abc import ABC, abstractmethod
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from accounts.models import User


class LoginCase(ABC):

    def __init__(self):
        super().__init__()

    @abstractmethod
    def _getGroup(self) -> Group:
        pass

    @abstractmethod
    def _getUser(self) -> User:
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
            self._getGroup().permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self._getGroup().permissions.clear()

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self._getUser())
