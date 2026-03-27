from accounts.pbac.entities import Namespace, Principal, Request, Resource
from accounts.pbac.engine import engine
from .models import MetaBusinessUnit, MetaMachine, Tag


NAMESPACE_ID = "Inventory"


def get_namespace() -> Namespace:
    return engine.get_namespace("Inventory")


def get_mbu_resource(mbu: MetaBusinessUnit) -> Resource:
    return Resource("MetaBusinessUnit", str(mbu.id), get_namespace())


def get_meta_machine_resource(machine: MetaMachine) -> Resource:
    entity_cache_name = "_pbac_resource"
    if not hasattr(machine, entity_cache_name):
        resource = Resource(
            "Machine", machine.serial_number, get_namespace(),
            [get_mbu_resource(mbu) for mbu in machine.meta_business_units]
        )
        setattr(machine, entity_cache_name, resource)
    return getattr(machine, entity_cache_name)


class BaseMachineTagRequest(Request):
    def __init__(self, user_obj, machine: MetaMachine, tag: Tag) -> None:
        namespace = get_namespace()
        action = engine.get_action(
            f"{self.operation}MachineTag",
            namespace,
            parents=[
                engine.get_action_group(f"{gbn}Actions", ns)
                for gbn in self.action_group_basenames
                for ns in (namespace, None)
            ],
        )
        resource = get_meta_machine_resource(machine)
        context = {"tagName": tag.name,
                   "tagID": tag.pk}
        taxonomy = tag.taxonomy
        if taxonomy:
            context["taxonomyName"] = taxonomy.name
            context["taxonomyID"] = taxonomy.pk
        super().__init__(
            Principal.from_user(user_obj),
            action,
            resource,
            context
        )


class CreateMachineTagRequest(BaseMachineTagRequest):
    operation = "create"
    action_group_basenames = ["Admin", "User"]


class DeleteMachineTagRequest(BaseMachineTagRequest):
    operation = "delete"
    action_group_basenames = ["Admin", "User"]


class ViewMachineTagRequest(BaseMachineTagRequest):
    operation = "view"
    action_group_basenames = ["Admin", "User", "Viewer"]
