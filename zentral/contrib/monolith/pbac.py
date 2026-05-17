from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace
from pbac.types import LEGACY_PERM_APPLIES_TO


# namespace


NAMESPACE_ID = "Monolith"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions
#
# syncRepository is only reachable via the legacy-perm path
# (user.has_perm("monolith.sync_repository")), so applies_to matches
# LEGACY_PERM_APPLIES_TO.


sync_repository_action = engine.register_action(
    "syncRepository",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="monolith.sync_repository",
)
