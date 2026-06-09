from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import (
    LEGACY_PERM_APPLIES_TO,
    SERVICE_ACCOUNT,
    SYSTEM,
    USER,
    AppliesTo,
    AttrSpec,
    ResourceType,
)

from .models import MetaBusinessUnit, MetaMachine, Tag

# namespace


NAMESPACE_ID = "Inventory"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resource types


MBU_RESOURCE_TYPE = ResourceType("MetaBusinessUnit", get_namespace())
MACHINE_RESOURCE_TYPE = ResourceType("Machine", get_namespace(), parents=(MBU_RESOURCE_TYPE,))


# actions
#
# createMachineTag and deleteMachineTag are reachable via two paths:
#   - PBACViewMixin -> Create/DeleteMachineTagRequest, with a Machine resource
#     and the tag context built from BaseMachineTagRequest below.
#   - the legacy-perm path (user.has_perm("inventory.{add,delete}_machinetag")),
#     which constructs a Request(... resource=engine.system_any_resource ...)
#     with an empty context.
#
# applies_to therefore lists both Machine and System as accepted resource
# types, and every context attribute is marked optional so the empty-context
# legacy requests remain valid.

_MACHINE_TAG_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(MACHINE_RESOURCE_TYPE, SYSTEM),
    context={
        "tagName": AttrSpec(str, required=False),
        "tagID": AttrSpec(int, required=False),
        "taxonomyName": AttrSpec(str, required=False),
        "taxonomyID": AttrSpec(int, required=False),
    },
)


create_machine_tag_action = engine.register_action(
    "createMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_MACHINE_TAG_APPLIES_TO,
    legacy_perm="inventory.add_machinetag",
)


delete_machine_tag_action = engine.register_action(
    "deleteMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_MACHINE_TAG_APPLIES_TO,
    legacy_perm="inventory.delete_machinetag",
)


# viewMachineTag has no typed PBAC request class today; it's only exercised
# via the legacy-perm path. Keep it at LEGACY_PERM_APPLIES_TO until a typed
# view path is introduced.
view_machine_tag_action = engine.register_action(
    "viewMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="inventory.view_machinetag",
)


# resources


def get_mbu_resource(mbu: MetaBusinessUnit) -> Resource:
    return Resource("MetaBusinessUnit", str(mbu.id), get_namespace())


def get_meta_machine_resource(machine: MetaMachine) -> Resource:
    # Cached in the meta machine object.
    # MBU membership changes or other changes within the lifetime of the object may lead to inconsistent decisions.
    entity_cache_name = "_pbac_resource"
    if not hasattr(machine, entity_cache_name):
        resource = Resource(
            "Machine", machine.serial_number, get_namespace(),
            [get_mbu_resource(mbu) for mbu in machine.meta_business_units]
        )
        setattr(machine, entity_cache_name, resource)
    return getattr(machine, entity_cache_name)


# requests

class BaseMachineTagRequest(Request):
    def __init__(self, user_obj, machine: MetaMachine, tag: Tag) -> None:
        resource = get_meta_machine_resource(machine)
        context = {"tagName": tag.name,
                   "tagID": tag.pk}
        taxonomy = tag.taxonomy
        if taxonomy:
            context["taxonomyName"] = taxonomy.name
            context["taxonomyID"] = taxonomy.pk
        super().__init__(
            Principal.from_user(user_obj),
            self.action,
            resource,
            context
        )


class CreateMachineTagRequest(BaseMachineTagRequest):
    action = create_machine_tag_action


class DeleteMachineTagRequest(BaseMachineTagRequest):
    action = delete_machine_tag_action
