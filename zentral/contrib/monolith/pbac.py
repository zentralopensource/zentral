from typing import Iterable

from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import LEGACY_PERM_APPLIES_TO, USER, AppliesTo, ResourceType

from zentral.contrib.inventory.pbac import MBU_RESOURCE_TYPE, get_mbu_resource_from_pk

from .models import Catalog, PkgInfo, Repository

# namespace


NAMESPACE_ID = "Monolith"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resource types


REPOSITORY_RESOURCE_TYPE = ResourceType("Repository", get_namespace(), parents=(MBU_RESOURCE_TYPE,))
CATALOG_RESOURCE_TYPE = ResourceType("Catalog", get_namespace(), parents=(REPOSITORY_RESOURCE_TYPE,))
PKG_INFO_RESOURCE_TYPE = ResourceType("PkgInfo", get_namespace(),
                                      parents=(REPOSITORY_RESOURCE_TYPE, CATALOG_RESOURCE_TYPE))


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
    help_text="Synchronize a Munki repository, and update the catalogs and the manifests.",
)


# the raw pkginfo carries the install check and pre/postinstall scripts, so it is
# not part of the viewer actions like the other monolith view permissions
#
# viewPkgInfoData takes the pkginfo as its resource, with its repository and all its
# catalogs as parents, so a policy can be scoped to one pkginfo, to a catalog, to a
# repository, or to the meta business unit that already scopes the machines. Nothing goes
# in the context: the catalogs are the containers of the pkginfo, and not parameters of the
# action. A scope on a catalog is existential - a pkginfo in that catalog and in another one
# matches it - so a restricted catalog is taken back with a forbid policy, and not with an
# allow list of catalogs. The archived catalogs are parents too: the data page shows the
# archived pkginfos, and the sync archives a catalog without active pkginfos, so a forbid on
# that catalog has to keep matching them.
#
# It costs one decision per pkginfo on the lists, which PkgInfo.objects.alles() does not
# paginate.
#
# It carries no legacy_perm: the typed PBAC path is the only way in. Only User principals:
# the pkginfo data has no API endpoint, so no service account can reach the action.


view_pkg_info_data_action = engine.register_action(
    "viewPkgInfoData",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER,),
        resources=(PKG_INFO_RESOURCE_TYPE,),
        context={},
    ),
    help_text="See the raw pkginfo of a package, as it is stored and as it is served in the catalogs.",
)


# resources


# Cached in the repository and in the catalog objects, so that the objects shared by the rows of a
# list give one entity for each id. Only the ids are read: the repository row carries icon_hashes,
# which grows with the repository.


def get_repository_resource(repository: Repository) -> Resource:
    entity_cache_name = "_pbac_resource"
    if not hasattr(repository, entity_cache_name):
        parents = []
        if repository.meta_business_unit_id:
            parents.append(get_mbu_resource_from_pk(repository.meta_business_unit_id))
        setattr(repository, entity_cache_name,
                Resource("Repository", str(repository.pk), get_namespace(), parents))
    return getattr(repository, entity_cache_name)


def get_catalog_resource(catalog: Catalog) -> Resource:
    entity_cache_name = "_pbac_resource"
    if not hasattr(catalog, entity_cache_name):
        setattr(catalog, entity_cache_name,
                Resource("Catalog", str(catalog.pk), get_namespace(),
                         [get_repository_resource(catalog.repository)]))
    return getattr(catalog, entity_cache_name)


def get_pkg_info_resource(pkg_info: PkgInfo, catalogs: Iterable[Catalog]) -> Resource:
    return Resource(
        "PkgInfo", str(pkg_info.pk), get_namespace(),
        [get_repository_resource(pkg_info.repository)] + [get_catalog_resource(c) for c in catalogs],
    )


# requests


class ViewPkgInfoDataRequest(Request):
    def __init__(self, user_obj, pkg_info: PkgInfo, catalogs: Iterable[Catalog]) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            view_pkg_info_data_action,
            get_pkg_info_resource(pkg_info, catalogs),
        )
