import datetime
import logging
import re
from django.http import HttpResponse
from django.urls import reverse
from rest_framework.exceptions import NotFound
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.utils.encoders import JSONEncoder
from rest_framework.views import APIView, exception_handler
from accounts.api_authentication import APITokenAuthentication
from realms.models import Realm, RealmGroup, RealmUser
from zentral.conf import settings
from zentral.utils.drf import DefaultDjangoModelPermissions
from .models import realm_group_members_updated
from .scim import SCIMUser, SCIMException, SCIMGroup


logger = logging.getLogger("zentral.realms.scim_views")


class SCIMAuthentication(APITokenAuthentication):
    keyword = "Bearer"


class SCIMParser(JSONParser):
    media_type = 'application/scim+json'


class SCIMEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            dt = obj.isoformat(timespec="milliseconds")
            return f"{dt}Z"
        else:
            return super().default(obj)


class SCIMRenderer(JSONRenderer):
    media_type = 'application/scim+json'
    encoder_class = SCIMEncoder


class SCIMPermissions(DefaultDjangoModelPermissions):
    def get_all_perms(self):
        perms = []
        for model in (RealmUser, RealmGroup):
            kwargs = {"app_label": model._meta.app_label,
                      "model_name": model._meta.model_name}
            for method_perms in self.perms_map.values():
                for method_perm in method_perms:
                    perm = method_perm % kwargs
                    if perm not in perms:
                        perms.append(perm)
        return perms

    def has_permission(self, request, view):
        # Authenticated user
        if not request.user or not request.user.is_authenticated:
            return False
        if view.model_class:
            # Directly use the model_class and the parent's mapping
            perms = self.get_required_permissions(request.method, view.model_class)
            # Not PUT → GET implicitly
            return request.user.has_perms(perms)
        else:
            for perm in self.get_all_perms():
                if request.user.has_perm(perm):
                    return True
        return False


def scim_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None:
        response.data.update({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": response.status_code
        })
        if isinstance(exc, SCIMException):
            response.data["scimType"] = exc.scim_type
    return response


class SCIMView(APIView):
    authentication_classes = [SCIMAuthentication]
    parser_classes = [SCIMParser]
    permission_classes = [SCIMPermissions]
    renderer_classes = [SCIMRenderer]
    model_class = None

    def get_exception_handler(self):
        return scim_exception_handler

    def get_realm(self):
        try:
            self.realm = Realm.objects.get(pk=self.kwargs["realm_pk"])
        except Realm.DoesNotExist:
            raise NotFound("Unknown Realm.")
        if not self.realm.scim_enabled:
            raise NotFound("SCIM not enabled on this Realm.")

    def get_resource_type(self):
        if self.model_class == RealmUser:
            return "User"
        elif self.model_class == RealmGroup:
            return "Group"

    def get_queryset(self):
        return self.model_class.objects.filter(realm=self.realm).order_by("created_at")

    def get_path(self, url_name, *args):
        full_url_name = f"realms_public:{url_name}"
        all_args = (self.realm.pk,) + args
        return reverse(full_url_name, args=all_args)

    def get_location(self, url_name, *args):
        return "https://{}{}".format(settings["api"]["fqdn"], self.get_path(url_name, *args))

    @staticmethod
    def build_response(data, status):
        return Response(data, status=status, content_type="application/scim+json")

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        self.get_realm()


class SingleResourceSCIMView(SCIMView):
    serializer = None

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        try:
            self.resource = self.get_queryset().get(pk=self.kwargs["pk"])
        except self.model_class.DoesNotExist:
            raise NotFound(detail=f"{self.get_resource_type()} not found.")

    def get(self, request, *args, **kwargs):
        return self.build_response(self.serialize_resource(self.resource), status=200)

    def put(self, request, *args, **kwargs):
        serializer = self.serializer(realm=self.realm, resource=self.resource, data=request.data, request=request)
        if serializer.is_valid():
            resource = serializer.update()
            return self.build_response(self.serialize_resource(resource), status=200)
        else:
            logger.error("Invalid input for %s update: %s", self.model_class.__name__, serializer.errors)
        raise SCIMException(detail="Invalid input.", scim_type="invalidSyntax")


class MultipleResourcesSCIMView(SCIMView):
    MAX_COUNT = 500
    DEFAULT_COUNT = 100
    serializer = None

    def get_pagination_params(self):
        try:
            start_index = max(1, int(self.kwargs["startIndex"]))
        except (KeyError, ValueError):
            start_index = 1
        try:
            count = min(self.MAX_COUNT, int(self.kwargs["count"]))
        except (KeyError, ValueError):
            count = self.DEFAULT_COUNT
        return start_index, count

    def filter_queryset(self, queryset, filter_exp):
        # by default, reject all filters
        raise SCIMException(detail="This filter is not supported.", scim_type="invalidFilter")

    def get_resources(self):
        queryset = self.get_queryset()
        filter_exp = self.request.GET.get("filter")
        if filter_exp:
            filter_exp = filter_exp.strip()
            if filter_exp:
                queryset = self.filter_queryset(queryset, filter_exp)
        self.queryset = queryset
        self.queryset_count = self.queryset.count()
        self.start_index, self.count = self.get_pagination_params()
        self.resources = self.queryset[self.start_index - 1:self.start_index + self.count - 1]

    def get(self, request, *args, **kwargs):
        self.get_resources()
        data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": self.queryset_count,
            "startIndex": self.start_index,
            "itemsPerPage": self.count,
            "Resources": []
        }
        for resource in self.resources:
            data["Resources"].append(self.serialize_resource(resource))
        return self.build_response(data, status="200")

    def post(self, request, *args, **kwargs):
        serializer = self.serializer(realm=self.realm, data=request.data, request=request)
        if serializer.is_valid():
            resource = serializer.save()
            return self.build_response(self.serialize_resource(resource), status=201)
        else:
            logger.error("Invalid input for %s creation: %s", self.model_class.__name__, serializer.errors)
        raise SCIMException(detail="Invalid input.", scim_type="invalidSyntax")


# Resource Types


class ResourceTypeMixin:
    def serialize_resource(self, resource_type):
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": resource_type,
            "name": resource_type,
            "description": resource_type,
            "endpoint": self.get_path(f"scim_{resource_type.lower()}s"),
            "schema": f"urn:ietf:params:scim:schemas:core:2.0:{resource_type}",
            "meta": {
                "location": self.get_location("scim_resource_type", resource_type),
                "resourceType": "ResourceType",
            }
        }


class ResourceTypesView(ResourceTypeMixin, SCIMView):
    def get(self, request, *args, **kwargs):
        return self.build_response([
            self.serialize_resource(resource_type)
            for resource_type in ("User", "Group")
        ], status=200)


class ResourceTypeView(ResourceTypeMixin, SCIMView):
    def get(self, request, *args, **kwargs):
        resource_type = kwargs["resource_type"]
        if resource_type not in ("User", "Group"):
            raise NotFound(detail="Unknown resource type.")
        return self.build_response(
            self.serialize_resource(resource_type),
            status=200
        )


# Schemas


class SchemasView(SCIMView):
    def get(self, request, *args, **kwargs):
        return self.build_response({}, status=200)


# Service provider config


class ServiceProviderConfigView(SCIMView):
    def get(self, request, *args, **kwargs):
        return self.build_response({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {
                "supported": True,
            },
            "bulk": {
                "supported": False,
                "maxOperations": 0,
                "maxPayloadSize": 0,
            },
            "filter": {
                "supported": False,
                "maxResults": MultipleResourcesSCIMView.MAX_COUNT,
            },
            "changePassword": {
                "supported": False,
            },
            "sort": {
                "supported": False,
            },
            "etag": {
                "supported": False,
            },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth2 Bearer Token Standard",
            }],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": self.get_location("scim_sp_config")
            },
        }, status=200)


# Users


class UserMixin:
    model_class = RealmUser
    serializer = SCIMUser

    def get_queryset(self):
        queryset = super().get_queryset().select_related("realm")
        if self.request.method == "GET":
            queryset = queryset.prefetch_related("realmemail_set", "groups")
        return queryset

    def serialize_resource(self, resource, **opts):
        data = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": resource.pk,
            "externalId": resource.scim_external_id,
            "userName": resource.username,
            "displayName": resource.get_full_name(),
            "active": resource.scim_active,
            "emails": [],
            "groups": [],
            "meta": {
                "resourceType": "User",
                "created": resource.created_at,
                "last_modified": resource.updated_at,
                "location": self.get_location("scim_user", resource.pk),
            }
        }
        # name
        name = {}
        for scim_attr, rsrc_attr in (("givenName", "first_name"),
                                     ("familyName", "last_name"),
                                     ("formatted", "get_full_name")):
            val = getattr(resource, rsrc_attr)
            if callable(val):
                val = val()
            if val:
                name[scim_attr] = val
        if name:
            data["name"] = name
        # emails
        for email in resource.realmemail_set.all():
            data["emails"].append({
                "primary": email.primary,
                "type": email.type,
                "value": email.email
            })
        # groups
        for group in resource.iter_raw_groups():
            group["$ref"] = self.get_location("scim_group", group["value"])
            data["groups"].append(group)
        return data


class UsersView(UserMixin, MultipleResourcesSCIMView):
    def filter_queryset(self, queryset, filter_exp):
        # TODO: support more expressions
        match = re.match(r'^userName\s+eq\s+"([^"]+)"$', filter_exp)
        if match:
            username = match.group(1)
            return queryset.filter(username=username)
        raise SCIMException(detail="This filter is not supported.", scim_type="invalidFilter")


class UserView(UserMixin, SingleResourceSCIMView):
    pass


# Groups


class GroupMixin:
    model_class = RealmGroup
    serializer = SCIMGroup

    def serialize_resource(self, resource, include_members=False):
        data = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": resource.pk,
            "externalId": resource.scim_external_id,
            "displayName": resource.display_name,
            "members": [],
            "meta": {
                "resourceType": "Group",
                "created": resource.created_at,
                "last_modified": resource.updated_at,
                "location": self.get_location("scim_group", resource.pk),
            }
        }
        for group in resource.realmgroup_set.all():
            data["members"].append({
                "value": str(group.pk),
                "type": "Group",
                "$ref": self.get_location("scim_group", group.pk),
            })
        for user in resource.realmuser_set.all():
            data["members"].append({
                "value": str(user.pk),
                "type": "User",
                "$ref": self.get_location("scim_user", user.pk),
            })
        return data


class GroupsView(GroupMixin, MultipleResourcesSCIMView):
    def filter_queryset(self, queryset, filter_exp):
        # TODO: support more expressions
        match = re.match(r'^displayName\s+eq\s+"([^"]+)"$', filter_exp)
        if match:
            display_name = match.group(1)
            return queryset.filter(display_name=display_name)
        raise SCIMException(detail="This filter is not supported.", scim_type="invalidFilter")


class GroupView(GroupMixin, SingleResourceSCIMView):
    def delete(self, request, *args, **kwargs):
        self.resource.delete()
        realm_group_members_updated.send_robust(self.__class__, realm=self.realm, request=request)
        return HttpResponse(status=204)
