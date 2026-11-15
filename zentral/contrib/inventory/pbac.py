import logging
from typing import Optional

from django.db.models import Exists, OuterRef, Q
from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.scoping import SQLMap, id_value, values_q, visible_rows
from pbac.utils import refused_requests
from pbac.types import (
    LEGACY_PERM_APPLIES_TO,
    SERVICE_ACCOUNT,
    SYSTEM,
    USER,
    AppliesTo,
    AttrSpec,
    ResourceType,
)

from .models import MachineSnapshot, MetaBusinessUnit, MetaMachine, Tag, Taxonomy, share_lock_rows

logger = logging.getLogger("zentral.contrib.inventory.pbac")


# namespace


NAMESPACE_ID = "Inventory"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resource types


MBU_RESOURCE_TYPE = ResourceType("MetaBusinessUnit", get_namespace())
MACHINE_RESOURCE_TYPE = ResourceType("Machine", get_namespace(), parents=(MBU_RESOURCE_TYPE,))
# A tag has its taxonomy as its only container, not its meta business unit. On a machine,
# `resource in Inventory::MetaBusinessUnit::"…"` means the machines of the business unit. On a tag, it would
# mean the tags that belong to the business unit, on any machine.
TAXONOMY_RESOURCE_TYPE = ResourceType("Taxonomy", get_namespace(), attrs={
    "name": AttrSpec(str, help_text="The name of the taxonomy."),
})
TAG_RESOURCE_TYPE = ResourceType("Tag", get_namespace(), attrs={
    "name": AttrSpec(str, help_text="The name of the tag."),
}, parents=(TAXONOMY_RESOURCE_TYPE,))


# actions
#
# createMachineTag and deleteMachineTag take the machine, with the tag in the context. They have no
# legacy perm: a decision on System::"any" never matches a policy scoped to machines, so a forbid on a
# meta business unit would not apply to it.

_MACHINE_TAG_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(MACHINE_RESOURCE_TYPE,),
    context={
        "tagName": AttrSpec(str, help_text="The name of the tag."),
        "tagID": AttrSpec(int, help_text="The primary key of the tag."),
        "taxonomyName": AttrSpec(
            str, required=False,
            help_text="The name of the taxonomy of the tag. It is absent if the tag has no taxonomy.",
        ),
        "taxonomyID": AttrSpec(
            int, required=False,
            help_text="The primary key of the taxonomy of the tag. It is absent if the tag has no taxonomy.",
        ),
    },
)


create_machine_tag_action = engine.register_action(
    "createMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_MACHINE_TAG_APPLIES_TO,
    help_text="Add a tag to a machine.",
)


delete_machine_tag_action = engine.register_action(
    "deleteMachineTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_MACHINE_TAG_APPLIES_TO,
    help_text="Remove a tag from a machine.",
)


# tagAnyMachine takes the tag, not the machine: it is for the writes that name machines by serial number or by
# principal user, and a serial number that is not in the inventory yet. A decision on such a machine would tell
# whether it exists, so a policy scoped to machines never limits the action. A policy such as
# `resource in Inventory::Taxonomy::"…"` covers the tags of a taxonomy.


tag_any_machine_action = engine.register_action(
    "tagAnyMachine",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(TAG_RESOURCE_TYPE,),
    ),
    help_text="Give the tag to machines, or remove it from them, whatever the machines are.",
)


# createTag takes the container of the new tag: its taxonomy, or System::"root" for a tag without taxonomy.
# It has no context: an object that creates tags later, such as a Jamf tag configuration, does not know their
# names when it is saved. It has no legacy perm, so `inventory.add_tag` gives nothing.


create_tag_action = engine.register_action(
    "createTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(TAXONOMY_RESOURCE_TYPE, SYSTEM),
    ),
    help_text="Create a tag in the taxonomy, or a tag without taxonomy on System::\"root\". "
              "It also authorizes the move of a tag to this taxonomy.",
)


# viewTag, updateTag and deleteTag take the tag. They have no legacy perm, so `inventory.view_tag`,
# `inventory.change_tag` and `inventory.delete_tag` give nothing. A move decides two resources: updateTag on the
# tag, which carries the taxonomy that it leaves, and createTag on the taxonomy that it joins.
#
# viewTag is for the list of the tags and for the detail of a tag only. A form of another module that uses tags
# as a condition shows every tag: the name of a tag is not a secret.

_TAG_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(TAG_RESOURCE_TYPE,),
)


view_tag_action = engine.register_action(
    "viewTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER],
    applies_to=_TAG_APPLIES_TO,
    help_text="See the tag in the list of the tags.",
)


update_tag_action = engine.register_action(
    "updateTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_TAG_APPLIES_TO,
    help_text="Update the tag. A move to another taxonomy also needs createTag on that taxonomy.",
)


delete_tag_action = engine.register_action(
    "deleteTag",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_TAG_APPLIES_TO,
    help_text="Delete the tag. A tag that a machine or an object uses cannot be deleted.",
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


def _taxonomy_resource(taxonomy: Taxonomy, name: str) -> Resource:
    return Resource("Taxonomy", str(taxonomy.pk), get_namespace(), attrs={"name": name})


def get_taxonomy_resource(taxonomy: Taxonomy) -> Resource:
    return _taxonomy_resource(taxonomy, taxonomy.name)


def _tag_resource(tag: Tag, name: str, taxonomy: Optional[Taxonomy]) -> Resource:
    parents = []
    if taxonomy:
        parents.append(get_taxonomy_resource(taxonomy))
    return Resource("Tag", str(tag.pk), get_namespace(), parents, attrs={"name": name})


def get_tag_resource(tag: Tag) -> Resource:
    return _tag_resource(tag, tag.name, tag.taxonomy)


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


class BaseTagRequest(Request):
    row_relations = ("taxonomy",)
    # the same parent and attributes as get_tag_resource
    sql_map = SQLMap(
        Tag, TAG_RESOURCE_TYPE,
        entities={TAG_RESOURCE_TYPE: "pk", TAXONOMY_RESOURCE_TYPE: "taxonomy"},
        attributes={"name": "name"},
    )

    def __init__(self, user_obj, tag: Tag) -> None:
        super().__init__(Principal.from_user(user_obj), self.pbac_action, get_tag_resource(tag))

    @classmethod
    def requests_for_rows(cls, user_obj, tags):
        return [cls(user_obj, tag) for tag in tags]


class TagAnyMachineRequest(BaseTagRequest):
    pbac_action = tag_any_machine_action


class ViewTagRequest(BaseTagRequest):
    pbac_action = view_tag_action


class UpdateTagRequest(BaseTagRequest):
    pbac_action = update_tag_action


class DeleteTagRequest(BaseTagRequest):
    pbac_action = delete_tag_action


class CreateTagRequest(Request):
    pbac_action = create_tag_action
    row_relations = ()
    # the rows are the taxonomies. The same attributes as get_taxonomy_resource.
    sql_map = SQLMap(
        Taxonomy, TAXONOMY_RESOURCE_TYPE,
        entities={TAXONOMY_RESOURCE_TYPE: "pk"},
        attributes={"name": "name"},
    )

    def __init__(self, user_obj, taxonomy: Optional[Taxonomy]) -> None:
        resource = get_taxonomy_resource(taxonomy) if taxonomy else engine.system_root_resource
        super().__init__(Principal.from_user(user_obj), self.pbac_action, resource)

    @classmethod
    def requests_for_rows(cls, user_obj, taxonomies):
        return [cls(user_obj, taxonomy) for taxonomy in taxonomies]


# An object that tags later: an enrollment, a query, a script, a group mapping. A device or a task writes its
# tags on machines, with no decision. So each save of the object decides tagAnyMachine on each tag that the
# object has after the save. A refused tag gets the answer of an unknown tag: the primary keys can be guessed.


def tags_for_any_machine(user_obj, queryset=None):
    """The tags of the queryset that the user can give to any machine, as a queryset. One decision for all."""
    if queryset is None:
        queryset = Tag.objects.all()
    return visible_rows(user_obj, TagAnyMachineRequest, queryset)


def taxonomies_for_create_tag(user_obj, queryset=None):
    """The taxonomies of the queryset in which the user can create a tag, as a queryset."""
    if queryset is None:
        queryset = Taxonomy.objects.all()
    return visible_rows(user_obj, CreateTagRequest, queryset)


def locked_rows(request_class, model, pks):
    """The rows to decide request_class on, read again after a share lock on them and on their row_relations.

    A row that a delete removed is missing. A rename or a move of a row, or of its parent, cannot commit between
    the decision and the write, so the decision is on the attributes that the write gives.
    """
    pks = share_lock_rows(model, pks)
    for relation in request_class.row_relations:
        field = model._meta.get_field(relation)
        related_pks = (model._base_manager.filter(pk__in=pks, **{f"{field.attname}__isnull": False})
                       .values_list(field.attname, flat=True))
        share_lock_rows(field.related_model, related_pks)
    return list(model._base_manager.select_related(*request_class.row_relations).filter(pk__in=pks).order_by("pk"))


def refused_pks(http_request, user_obj, request_class, objects):
    """Decide request_class on each object in one batch, and return the primary keys of the refused ones.

    The decision is on the rows read again under a lock, see locked_rows. Each refusal is logged. An object that a
    delete removed since it was read is refused too, as an unknown one.
    """
    objects = list(objects)
    if not objects:
        return set()
    current_rows = locked_rows(request_class, type(objects[0]), [obj.pk for obj in objects])
    pbac_requests = [request_class(user_obj, row) for row in current_rows]
    refused_requests(http_request, pbac_requests)
    refused = {obj.pk for obj in objects} - {row.pk for row in current_rows}
    refused.update(row.pk for row, pbac_request in zip(current_rows, pbac_requests) if not pbac_request.is_authorized)
    return refused


def renamed_tag_request(user_obj, tag, name, taxonomy):
    """updateTag on the tag with its new name. The name is an attribute that the policies can match."""
    return Request(Principal.from_user(user_obj), update_tag_action, _tag_resource(tag, name, taxonomy))


def renamed_taxonomy_request(user_obj, taxonomy, name):
    """createTag on the taxonomy with its new name.

    The name is an attribute that the createTag policies can match, so a rename can give createTag on the taxonomy.
    """
    return Request(Principal.from_user(user_obj), create_tag_action, _taxonomy_resource(taxonomy, name))


def taxonomies_for_tag_creation_later(user_obj, queryset=None):
    """The taxonomies that the user can give to an object that creates and sets their tags later.

    The object sets the tags of the taxonomy on machines: it gives some and removes the others, and it creates
    the missing ones. So the user needs createTag on the taxonomy, and tagAnyMachine on each tag that it has.
    """
    refused_tags_queryset = Tag.objects.filter(taxonomy__isnull=False).exclude(
        pk__in=tags_for_any_machine(user_obj).values("pk")
    )
    return taxonomies_for_create_tag(user_obj, queryset).exclude(pk__in=refused_tags_queryset.values("taxonomy"))


def refused_taxonomies_for_tag_creation_later(http_request, user_obj, taxonomies):
    """The primary keys of the taxonomies with a refused createTag, or a refused tagAnyMachine on one of its tags.

    The decisions are on the rows read again under a lock, see locked_rows. A taxonomy that a delete removed since
    it was read is refused too, as an unknown one.
    """
    taxonomies = list(taxonomies)
    current_taxonomies = locked_rows(CreateTagRequest, Taxonomy, [taxonomy.pk for taxonomy in taxonomies])
    # the tags of all the taxonomies, locked in one batch, and grouped by the taxonomy read again
    taxonomy_tags = {taxonomy.pk: [] for taxonomy in current_taxonomies}
    for tag in locked_rows(TagAnyMachineRequest, Tag,
                           Tag.objects.filter(taxonomy__in=taxonomy_tags).values_list("pk", flat=True)):
        if tag.taxonomy_id in taxonomy_tags:
            taxonomy_tags[tag.taxonomy_id].append(tag)
    decisions = [(taxonomy, [CreateTagRequest(user_obj, taxonomy)]
                  + [TagAnyMachineRequest(user_obj, tag) for tag in taxonomy_tags[taxonomy.pk]])
                 for taxonomy in current_taxonomies]
    refused_requests(http_request, [pbac_request for _, pbac_requests in decisions for pbac_request in pbac_requests])
    refused = {taxonomy.pk for taxonomy in taxonomies} - {taxonomy.pk for taxonomy in current_taxonomies}
    refused.update(taxonomy.pk for taxonomy, pbac_requests in decisions
                   if not all(pbac_request.is_authorized for pbac_request in pbac_requests))
    return refused
