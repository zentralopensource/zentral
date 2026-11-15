from rest_framework.permissions import SAFE_METHODS

from pbac.engine import ActionGroupBasename, engine
from pbac.types import SERVICE_ACCOUNT, USER, AppliesTo, ResourceType
from pbac.utils import permitted_pks


# A response without the view…Secrets action of the object has the hash of each secret, as the events
# show it: a client sees that a secret changed, not its value.


def register_view_secrets_action(id: str, resource_type: ResourceType, help_text: str):
    return engine.register_action(
        id,
        resource_type.namespace,
        [ActionGroupBasename.ADMIN],
        applies_to=AppliesTo(
            principals=(USER, SERVICE_ACCOUNT),
            resources=(resource_type,),
            context={},
        ),
        help_text=help_text,
    )


# API


SECRETS_CONTEXT_KEY = "pks_with_secrets"
ALL_SECRETS = object()


class SecretsAPIViewMixin:
    """Decides the secrets of the objects of a read, in one batch. A hidden secret is a filter: no log (rule 14).

    A write response gives back the secrets that the body carried, with no decision. Only for a serializer
    that writes each secret from the body: a secret that Zentral keeps when the body leaves it out needs a
    decision in the write response too.
    """
    view_secrets_request_class = None

    def get_serializer(self, *args, **kwargs):
        serializer = super().get_serializer(*args, **kwargs)
        if self.request.method not in SAFE_METHODS:
            pks_with_secrets = ALL_SECRETS
        elif args:
            objects = args[0] if kwargs.get("many") else [args[0]]
            pks_with_secrets = permitted_pks(self.request.user, self.view_secrets_request_class, objects)
        else:
            pks_with_secrets = set()
        serializer.context[SECRETS_CONTEXT_KEY] = pks_with_secrets
        return serializer


class SecretsSerializerMixin:
    """Replaces the secrets with their hashes, unless the view permits them. Without a decision, the hashes."""

    def has_secrets_permission(self, instance):
        pks_with_secrets = self.context.get(SECRETS_CONTEXT_KEY)
        return pks_with_secrets is ALL_SECRETS or (pks_with_secrets is not None and instance.pk in pks_with_secrets)

    def hash_secrets(self, instance, ret):
        raise NotImplementedError

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if not self.has_secrets_permission(instance):
            self.hash_secrets(instance, ret)
        return ret


class BackendInstanceSecretsSerializerMixin(SecretsSerializerMixin):
    """The options of the backend of a BackendInstance, in the <backend>_kwargs field."""

    def hash_secrets(self, instance, ret):
        kwargs_key = f"{instance.backend.lower()}_kwargs"
        if ret.get(kwargs_key):
            ret[kwargs_key] = instance.hash_backend_kwargs(ret[kwargs_key])
