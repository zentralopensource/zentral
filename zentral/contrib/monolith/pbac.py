from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace


# namespace


NAMESPACE_ID = "Monolith"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions


sync_repository_action = engine.get_action(
    "syncRepository",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "monolith.sync_repository",
)
