from django.db.models import Exists, OuterRef, Q
from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.scoping import id_value, values_q
from pbac.types import (
    LEGACY_PERM_APPLIES_TO,
    SERVICE_ACCOUNT,
    SYSTEM,
    USER,
    AppliesTo,
    AttrSpec,
    ResourceType,
)

from .models import MachineSnapshot, MetaBusinessUnit, MetaMachine, Tag

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
        "tagName": AttrSpec(
            str, required=False,
            help_text="The name of the tag. It is absent if the request does not identify a tag.",
        ),
        "tagID": AttrSpec(
            int, required=False,
            help_text="The primary key of the tag. It is absent if the request does not identify a tag.",
        ),
        "taxonomyName": AttrSpec(
            str, required=False,
            help_text="The name of the taxonomy of the tag. It is absent if the tag has no taxonomy, "
                      "or if the request does not identify a tag.",
        ),
        "taxonomyID": AttrSpec(
            int, required=False,
            help_text="The primary key of the taxonomy of the tag. It is absent if the tag has no taxonomy, "
                      "or if the request does not identify a tag.",
        ),
    },
)


create_machine_tag_action = engine.register_action(
    "createMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_MACHINE_TAG_APPLIES_TO,
    legacy_perm="inventory.add_machinetag",
    help_text="Add a tag to a machine.",
)


delete_machine_tag_action = engine.register_action(
    "deleteMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_MACHINE_TAG_APPLIES_TO,
    legacy_perm="inventory.delete_machinetag",
    help_text="Remove a tag from a machine.",
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
    help_text="See the tags of a machine.",
)


# resources


def get_mbu_resource(mbu: MetaBusinessUnit) -> Resource:
    return get_mbu_resource_from_pk(mbu.id)


def get_mbu_resource_from_pk(mbu_pk: int) -> Resource:
    return Resource("MetaBusinessUnit", str(mbu_pk), get_namespace())


def get_meta_machine_resource(machine: MetaMachine) -> Resource:
    # Cached in the meta machine object.
    # MBU membership changes or other changes within the lifetime of the object may lead to inconsistent decisions.
    entity_cache_name = "_pbac_resource"
    if not hasattr(machine, entity_cache_name):
        # the url safe serial number, not the raw one: a serial comes from a device and can carry
        # characters cedar cannot read in an entity id, and this is the form the machine URL and
        # the links to it already use
        resource = Resource(
            "Machine", machine.get_urlsafe_serial_number(), get_namespace(),
            [get_mbu_resource(mbu) for mbu in machine.meta_business_units]
        )
        setattr(machine, entity_cache_name, resource)
    return getattr(machine, entity_cache_name)


def get_machine_sql_entities(serial_number_lookup):
    """The machine and its meta business units, for the pbac.scoping.SQLMap of a row with a serial number.

    They must give the same answers as get_meta_machine_resource.
    """

    def machine(entity_ids):
        serial_numbers = []
        for entity_id in entity_ids:
            try:
                serial_number = MetaMachine.from_urlsafe_serial_number(entity_id).serial_number
            except ValueError:
                continue
            if MetaMachine.make_urlsafe_serial_number(serial_number) == entity_id:
                serial_numbers.append(serial_number)
        return values_q(serial_number_lookup, serial_numbers)

    def meta_business_unit(entity_ids):
        pks = (id_value(MetaBusinessUnit._meta.pk, entity_id) for entity_id in entity_ids)
        mbu_q = values_q("business_unit__meta_business_unit", (pk for pk in pks if pk is not None))
        if mbu_q is False:
            return False
        # the set of MetaMachine.meta_business_units: the current snapshots, API enrollment included
        return Q(Exists(MachineSnapshot.objects.current().filter(mbu_q,
                                                                 serial_number=OuterRef(serial_number_lookup))))

    return {MACHINE_RESOURCE_TYPE: machine, MBU_RESOURCE_TYPE: meta_business_unit}


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
