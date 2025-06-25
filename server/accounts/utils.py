import functools
import operator
from django.apps import apps
from django.contrib.auth.models import Permission
from django.db.models import Q


def all_permissions_queryset():
    # auth.group by default
    content_type_filters = [
        Q(content_type__app_label=a, content_type__model=m) for a, m in (
             ("auth", "group"),
        )
    ]
    # all configured apps
    for app_name, app_config in apps.app_configs.items():
        permission_models = getattr(app_config, "permission_models", None)
        if permission_models:
            for model in permission_models:
                content_type_filters.append(Q(content_type__app_label=app_name, content_type__model=model))
    # return filtered permissions
    return Permission.objects.select_related(
        "content_type",
    ).filter(
        functools.reduce(
            operator.or_,
            content_type_filters
        )
    ).order_by(
        "content_type__app_label",
        "content_type__model",
        "codename",
    )


def all_permissions():
    for permission in all_permissions_queryset():
        model_class = permission.content_type.model_class()
        custom = permission.codename in [codename for codename, _ in model_class._meta.permissions]
        read_only = not custom and permission.codename.startswith("view_")
        yield permission, read_only, custom
