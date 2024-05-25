from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from itertools import chain
import json
import logging
import os.path
import plistlib
import re
import unicodedata
import urllib.parse
from django.core.exceptions import ObjectDoesNotExist
from django.db import models, connection
from django.db.models import Count, F, Q
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import slugify
from zentral.contrib.inventory.models import BaseEnrollment, MetaBusinessUnit, Tag
from zentral.utils.text import get_version_sort_key
from .conf import monolith_conf
from .repository_backends import RepositoryBackend, get_repository_backend, load_repository_backend
from .utils import build_manifest_enrollment_package


logger = logging.getLogger("zentral.contrib.monolith.models")


# PkgInfo / Catalog / Manifest


class MunkiNameError(Exception):
    pass


def build_munki_name(model, key, name, ext=None):
    # first, the model
    elements = [model.replace("_", "-")]

    # then, the primary keys
    if isinstance(key, list):
        key = "-".join(str(int(pk)) for pk in key)
    else:
        key = str(int(key))
    elements.append(key)

    # then, a meaningful name
    # to ascii
    name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')
    # make it a slug, preserve some common separators
    name = re.sub(r'[^\w\s\._-]', '', name).strip()
    # replace all common separators by -
    name = re.sub(r'[\s\._-]+', '-', name).strip("-")
    elements.append(name or "-")

    # an eventual file extension
    if ext:
        elements.append(ext.replace(".", ""))

    return ".".join(elements)


def parse_munki_name(name):
    try:
        model, key, _ = name.split(".", 2)
        model = model.replace("-", "_")
        if "-" in key:
            key = [int(pk) for pk in key.split("-")]
        else:
            key = int(key)
        return model, key
    except (TypeError, ValueError):
        raise MunkiNameError


class RepositoryManager(models.Manager):
    def for_deletion(self):
        return self.annotate(
            # not linked to a manifest
            manifest_link_count=Count("catalog__manifestcatalog"),
        ).filter(manifest_link_count=0)

    def for_manual_catalogs(self):
        return self.filter(backend=RepositoryBackend.VIRTUAL)


class Repository(models.Model):
    name = models.CharField(max_length=256, unique=True)
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.SET_NULL, blank=True, null=True)
    backend = models.CharField(max_length=32, choices=RepositoryBackend.choices)
    backend_kwargs = models.JSONField(editable=False)
    icon_hashes = models.JSONField(editable=False, default=dict)
    client_resources = models.JSONField(editable=False, default=list)
    last_synced_at = models.DateTimeField(editable=False, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = RepositoryManager()

    class Meta:
        ordering = ("name",)
        permissions = [
            ("sync_repository", "Can sync repository"),
        ]

    def __str__(self):
        return self.name

    def can_be_deleted(self):
        return Repository.objects.for_deletion().filter(pk=self.pk).exists()

    def manifests(self):
        return Manifest.objects.distinct().filter(manifestcatalog__catalog__repository=self)

    def get_absolute_url(self):
        return reverse("monolith:repository", args=(self.pk,))

    def get_backend_kwargs(self):
        backend = load_repository_backend(self)
        return backend.get_kwargs()

    def get_backend_kwargs_for_event(self):
        backend = load_repository_backend(self)
        return backend.get_kwargs_for_event()

    def set_backend_kwargs(self, kwargs):
        backend = get_repository_backend(self)
        backend.set_kwargs(kwargs)

    def rewrap_secrets(self):
        backend = load_repository_backend(self)
        backend.rewrap_kwargs()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk,
             "name": self.name}
        if not keys_only:
            if self.meta_business_unit:
                d["meta_business_unit"] = self.meta_business_unit.serialize_for_event(keys_only=True)
            d.update({
                "backend": str(self.backend),
                "backend_kwargs": self.get_backend_kwargs_for_event(),
                "created_at": self.created_at,
                "updated_at": self.updated_at
            })
        return d

    def _get_BACKEND_kwargs(self, backend):
        if self.backend == backend:
            return self.get_backend_kwargs()

    def __getattr__(self, name):
        for backend in RepositoryBackend:
            if name == f"get_{backend.lower()}_kwargs":
                return partial(self._get_BACKEND_kwargs, backend)
        raise AttributeError


class CatalogManager(models.Manager):
    def for_deletion(self):
        return self.annotate(
            # no active pkg info
            pkginfo_count=Count("pkginfo", filter=Q(pkginfo__archived_at__isnull=True)),
            # not included in a manifest
            manifestcatalog_count=Count("manifestcatalog")
        ).filter(
            repository__backend=RepositoryBackend.VIRTUAL,
            pkginfo_count=0,
            manifestcatalog_count=0
        )

    def for_update(self):
        return self.filter(repository__backend=RepositoryBackend.VIRTUAL)

    def for_upload(self):
        return self.filter(repository__backend=RepositoryBackend.VIRTUAL)

    def available_for_manifest(self, manifest, add_only=False):
        qs = self.filter(
            Q(repository__meta_business_unit__isnull=True)
            | Q(repository__meta_business_unit=manifest.meta_business_unit)
        )
        if add_only:
            qs = qs.exclude(
                pk__in=[mc.catalog_id for mc in manifest.manifestcatalog_set.all()]
            )
        return qs


class Catalog(models.Model):
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived_at = models.DateTimeField(null=True, editable=False)

    objects = CatalogManager()

    class Meta:
        unique_together = (('repository', 'name'),)
        ordering = ('-archived_at', 'repository__name', 'name', 'pk')

    def __str__(self):
        return f"{self.repository} - {self.name}"

    def get_absolute_url(self):
        return reverse("monolith:catalog", args=(self.pk,))

    def get_pkg_info_url(self):
        return "{}?{}".format(reverse("monolith:pkg_infos"),
                              urllib.parse.urlencode({"catalog": self.pk}))

    def can_be_deleted(self):
        return Catalog.objects.for_deletion().filter(pk=self.pk).exists()

    def can_be_updated(self):
        return Catalog.objects.for_update().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk,
             "repository": self.repository.serialize_for_event(keys_only=True),
             "name": self.name}
        if not keys_only:
            d.update({"created_at": self.created_at,
                      "updated_at": self.updated_at})
            if self.archived_at:
                d["archived_at"] = self.archived_at
        return d


class PkgInfoCategoryManager(models.Manager):
    def for_upload(self):
        return self.filter(repository__backend=RepositoryBackend.VIRTUAL)


class PkgInfoCategory(models.Model):
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    name = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = PkgInfoCategoryManager()

    class Meta:
        unique_together = (('repository', 'name'),)

    def __str__(self):
        return self.name

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk,
             "repository": self.repository.serialize_for_event(keys_only=True),
             "name": self.name}
        if not keys_only:
            d["created_at"] = self.created_at
        return d


class PkgInfoNameManager(models.Manager):
    def for_deletion(self):
        return self.annotate(
            # no active pkg info
            pkginfo_count=Count("pkginfo", filter=Q(pkginfo__archived_at__isnull=True)),
            # not included in a sub manifest
            submanifest_count=Count("submanifestpkginfo")
        ).filter(pkginfo_count=0, submanifest_count=0)


class PkgInfoName(models.Model):
    name = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = PkgInfoNameManager()

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

    @cached_property
    def has_active_pkginfos(self):
        return self.pkginfo_set.filter(archived_at__isnull=True).count() > 0

    def manifests(self):
        return Manifest.objects.filter(manifestsubmanifest__sub_manifest__submanifestpkginfo__pkg_info_name=self)

    def can_be_deleted(self):
        return (
            self.submanifestpkginfo_set.count() == 0
            and self.pkginfo_set.filter(archived_at__isnull=True).count() == 0
        )

    def get_absolute_url(self):
        return reverse("monolith:pkg_info_name", args=(self.pk,))

    def serialize_for_event(self):
        return {"pk": self.pk, "name": self.name, "created_at": self.created_at}

    def linked_objects_keys_for_event(self):
        return {"munki_pkginfo_name": ((self.name,),)}


class PkgInfoManager(models.Manager):
    def local(self):
        return self.filter(local=True)

    def alles(self, **kwargs):
        include_empty_names = kwargs.get("include_empty_names", False)
        params = []
        # first we aggregate the package info, with the munki managed installs
        aggregated_pi_query = (
            "select pn.id as pn_pk, pn.name, pi.id as pi_pk, pi.version,"
            "pi.local, pi.data -> 'zentral_monolith' as pi_opts,"
            "count(mi.id), sum(count(mi.id)) over (partition by pn.id) as pn_total "
            "from monolith_pkginfoname as pn "
            "{left}join monolith_pkginfo as pi on (pi.name_id = pn.id) "
            "left join munki_managedinstall as mi on "
            "(pn.name = mi.name and pi.version = mi.installed_version) "
            "where pi.archived_at is null"
        ).format(left="left " if include_empty_names else "")
        name = kwargs.get("name")
        if name:
            params.append("%{}%".format(connection.ops.prep_for_like_query(name)))
            aggregated_pi_query += " and UPPER(pn.name) LIKE UPPER(%s)"
        name_id = kwargs.get("name_id")
        if name_id:
            params.append(name_id)
            aggregated_pi_query += " and pn.id = %s"
        aggregated_pi_query += " group by pn.id, pn.name, pi.id, pi.version, pi.data"

        # then we build the full query
        # join and aggregate the catalogs, compte the percentages
        query = (
            f"with aggregated_pi as ({aggregated_pi_query}) "
            "select api.*,"
            "case when pn_total=0 then null else 100.0 * count / pn_total end as percent,"
            "json_agg(distinct jsonb_build_object('pk', c.id, 'name', c.name)) as catalogs "
            "from aggregated_pi as api "
            "{left}join monolith_pkginfo_catalogs as pc on (pc.pkginfo_id = api.pi_pk) "
            "{left}join monolith_catalog as c on (c.id = pc.catalog_id) "
            "where c.archived_at is null "
        ).format(left="left " if include_empty_names else "")
        catalog = kwargs.get("catalog")
        if catalog:
            params.append(catalog.id)
            query += " and c.id = %s"
        query += (
            " group by api.pn_pk, api.name, api.pi_pk, api.version, api.local, api.pi_opts, api.count, api.pn_total "
            "order by api.name, api.pn_pk, api.pi_pk"
        )

        # run the query and organize the results
        cursor = connection.cursor()
        cursor.execute(query, params)
        current_pn = current_pn_pk = None
        name_c = info_c = 0
        pkg_name_list = []
        seen_tag_names = set([])
        pi_opts_with_tags = []
        for pn_pk, pn_name, pi_pk, version, pi_local, pi_opts, count, pn_total, percent, catalogs in cursor.fetchall():
            info_c += 1
            if pn_pk != current_pn_pk:
                if current_pn is not None:
                    current_pn['pkg_infos'].sort(key=lambda pi: pi["version_sort"], reverse=True)
                    pkg_name_list.append(current_pn)
                    name_c += 1
                current_pn_pk = pn_pk
                current_pn = {'id': pn_pk,
                              'name': pn_name,
                              'count': int(pn_total),
                              'pkg_infos': []}
            if pi_pk:
                pi = {'pk': pi_pk,
                      'version': version,
                      'version_sort': get_version_sort_key(version),
                      'local': pi_local,
                      'catalogs': sorted(catalogs, key=lambda c: c["name"]),
                      'count': int(count),
                      'percent': percent}
                if pi_opts:
                    pi_opts = json.loads(pi_opts)
                    pi['options'] = pi_opts
                    excluded_tags = pi_opts.get("excluded_tags")
                    shards = pi_opts.setdefault("shards", {})
                    modulo = shards.setdefault("modulo", 100)
                    shards.setdefault("default", modulo)
                    tag_shards = shards.get("tags")
                    if isinstance(excluded_tags, list) or isinstance(tag_shards, dict):
                        if excluded_tags:
                            seen_tag_names.update(excluded_tags)
                        if tag_shards:
                            seen_tag_names.update(tag_shards.keys())
                        pi_opts_with_tags.append(pi_opts)
                current_pn['pkg_infos'].append(pi)
        if current_pn:
            current_pn['pkg_infos'].sort(key=lambda pi: pi["version_sort"], reverse=True)
            pkg_name_list.append(current_pn)
            name_c += 1
        if seen_tag_names:
            # rehydrate the tags
            seen_tags = {
                tag.name: tag
                for tag in Tag.objects.select_related("meta_business_unit", "taxonomy").filter(name__in=seen_tag_names)
            }
            for pi_opts in pi_opts_with_tags:
                excluded_tags = pi_opts.pop("excluded_tags", None)
                if isinstance(excluded_tags, list):
                    pi_opts["excluded_tags"] = [
                        seen_tags[tag_name]
                        for tag_name in sorted(excluded_tags)
                        if tag_name in seen_tags
                    ]
                shards = pi_opts["shards"]
                tag_shards = shards.pop("tags", None)
                if isinstance(tag_shards, dict):
                    pi_opts["shards"]["tags"] = [
                        (seen_tags[tag_name], shard)
                        for tag_name, shard in sorted(tag_shards.items(), key=lambda t:t[0].lower())
                        if tag_name in seen_tags
                    ]
        return name_c, info_c, pkg_name_list


def pkg_info_path(instance, filename):
    # WARNING only works once the instance has been saved
    _, ext = os.path.splitext(filename)
    return f"monolith/packages/{instance.pk:08d}{ext}"


class PkgInfo(models.Model):
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    name = models.ForeignKey(PkgInfoName, on_delete=models.CASCADE)
    version = models.CharField(max_length=256)
    catalogs = models.ManyToManyField(Catalog)
    category = models.ForeignKey(PkgInfoCategory, on_delete=models.SET_NULL, null=True, blank=True)
    requires = models.ManyToManyField(PkgInfoName, related_name="required_by", blank=True)
    update_for = models.ManyToManyField(PkgInfoName, related_name="updated_by", blank=True)
    data = models.JSONField()
    local = models.BooleanField(default=False)
    file = models.FileField(upload_to=pkg_info_path, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived_at = models.DateTimeField(blank=True, null=True)

    objects = PkgInfoManager()

    class Meta:
        ordering = ('name', 'version')
        unique_together = (('name', 'version'),)

    def get_key(self):
        return (self.name.name, self.version)

    def __str__(self):
        return "{} {}".format(self.name, self.version)

    def active_catalogs(self):
        return self.catalogs.filter(archived_at__isnull=True)

    def get_original_icon_name(self):
        return self.data.get("icon_name") or f"{self.name.name}.png"

    def get_monolith_icon_name(self):
        icon_name = self.data.get("icon_name")
        if icon_name:
            root, ext = os.path.splitext(icon_name)
            name = os.path.basename(root)
        else:
            ext = ".png"
            name = self.name.name
        return build_munki_name("icon", self.id, name, ext)

    def get_pkg_info(self):
        pkg_info = self.data.copy()
        pkg_info.pop("catalogs", None)
        # replace package locations
        for attr in ("installer_item_location", "uninstaller_item_location"):
            loc = pkg_info.pop(attr, None)
            if loc:
                root, ext = os.path.splitext(loc)
                name = os.path.basename(root)
                model = attr.removesuffix("_location")
                pkg_info[attr] = build_munki_name(model, self.id, name, ext)
        # replace icon name
        pkg_info["icon_name"] = self.get_monolith_icon_name()
        return pkg_info

    def get_absolute_url(self):
        return "{}#{}".format(reverse("monolith:pkg_info_name", args=(self.name.id,)), self.pk)

    # shards

    @property
    def zentral_options(self):
        try:
            return self.data.get("zentral_monolith", {})
        except AttributeError:
            return {}

    @property
    def excluded_tags(self):
        return Tag.objects.filter(name__in=self.zentral_options.get("excluded_tags", []))

    @property
    def default_shard(self):
        shards = self.zentral_options.get("shards", {})
        return shards.get("default", 100)

    @property
    def shard_modulo(self):
        shards = self.zentral_options.get("shards", {})
        return shards.get("modulo", 100)

    @property
    def tag_shards(self):
        tag_shards = self.zentral_options.get("shards", {}).get("tags")
        if not tag_shards:
            return []
        tags = (
            Tag.objects.select_related("meta_business_unit", "taxonomy")
                       .filter(name__in=tag_shards.keys())
                       .order_by("name")
        )
        return [{"tag": tag, "shard": tag_shards[tag.name]} for tag in tags]

    # events

    def serialize_for_event(self, keys_only=False):
        d = {
            "pk": self.pk,
            "name": self.name.name,
            "version": self.version
        }
        if keys_only:
            return d
        d.update({
            "catalogs": [c.serialize_for_event(keys_only=True) for c in self.catalogs.all()],
            "requires": [pin.name for pin in self.requires.all().order_by("name")],
            "update_for": [pin.name for pin in self.update_for.all().order_by("name")],
            "data": self.data,
            "local": self.local,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        if self.archived_at:
            d["archived_at"] = self.archived_at
        if self.category:
            d["category"] = self.category.serialize_for_event(keys_only=True)
        return d

    def linked_objects_keys_for_event(self):
        return {"munki_pkginfo_name": ((self.name.name,),),
                "munki_pkginfo": ((self.name.name, self.version),)}


@dataclass
class CachedPkgInfo:
    pk: int
    repository_pk: int
    version: str
    file_name: str
    installer_item_location: str
    uninstaller_item_location: str
    icon_name: str
    name: str

    def get_repository_section_and_name(self, model):
        section = name = None
        if model == "installer_item":
            section = "pkgs"
            if self.file_name:
                name = self.file_name
            elif self.installer_item_location:
                name = self.installer_item_location
        elif model == "uninstaller_item" and self.uninstaller_item_location:
            section = "pkgs"
            name = self.uninstaller_item_location
        elif model == "icon":
            section = "icons"
            if self.icon_name:
                name = self.icon_name
            else:
                name = f"{self.name}.png"
        return section, name


SUB_MANIFEST_PKG_INFO_KEY_CHOICES = (
    ('managed_installs', 'Managed Installs'),
    ('managed_uninstalls', 'Managed Uninstalls'),
    ('default_installs', 'Default Installs'),
    ('optional_installs', 'Optional Installs'),
    ('managed_updates', 'Managed Updates'),
)
SUB_MANIFEST_PKG_INFO_KEY_CHOICES_DICT = dict(SUB_MANIFEST_PKG_INFO_KEY_CHOICES)


class SubManifest(models.Model):
    """Group of pkginfo or attachments (pkgs or scripts)."""

    # to restrict some sub manifests to a MBU
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.SET_NULL, blank=True, null=True)

    name = models.CharField(max_length=256)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        if self.meta_business_unit:
            return "{} / {}".format(self.meta_business_unit.name, self.name)
        else:
            return self.name

    def get_absolute_url(self):
        return reverse('monolith:sub_manifest', args=(self.pk,))

    def pkg_info_dict(self):
        pkg_info_d = {'keys': {},
                      'total': {'pkginfo': 0}}

        def iter_keys(key):
            yield key, SUB_MANIFEST_PKG_INFO_KEY_CHOICES_DICT[key]
            if key == "default_installs":
                yield "optional_installs", SUB_MANIFEST_PKG_INFO_KEY_CHOICES_DICT["optional_installs"]

        for smpi in self.submanifestpkginfo_set.select_related('pkg_info_name', 'condition'):
            for key, key_display in iter_keys(smpi.key):
                key_dict = pkg_info_d['keys'].setdefault(key,
                                                         {'key_display': key_display,
                                                          'key_list': []})
                key_dict['key_list'].append((smpi.pkg_info_name.name, smpi))
            pkg_info_d['total']['pkginfo'] += 1
        for key, key_d in pkg_info_d['keys'].items():
            key_d['key_list'].sort(key=lambda t: (t[0], -1 * t[1].pk))
        return pkg_info_d

    def get_munki_name(self):
        return build_munki_name("sub_manifest", self.id, self.name)

    def build(self):
        condition_d = {}
        featured_items = set()
        for key, key_d in self.pkg_info_dict()['keys'].items():
            for _, smpi in key_d['key_list']:
                if smpi.condition:
                    condition = smpi.condition.predicate
                else:
                    condition = None
                name = smpi.get_name()
                if isinstance(smpi, SubManifestPkgInfo):
                    options = smpi.options
                else:
                    options = None
                if key in ('managed_installs', 'optional_installs'):
                    val = (name, options)
                else:
                    val = name
                condition_d.setdefault(condition, {}).setdefault(key, []).append(val)
                if key != "managed_uninstalls" and smpi.featured_item:
                    featured_items.add(name)
        data = {}
        if featured_items:
            data["featured_items"] = sorted(featured_items)
        for condition, condition_key_d in condition_d.items():
            if condition is None:
                data.update(condition_key_d)
            else:
                condition_key_d["condition"] = condition
                data.setdefault("conditional_items", []).append(condition_key_d)
        return data

    def can_be_deleted(self):
        return self.manifestsubmanifest_set.all().count() == 0

    def manifests_with_tags(self):
        mwt = []
        for msn in (self.manifestsubmanifest_set.select_related("manifest__meta_business_unit")
                                                .prefetch_related("tags")
                                                .all()):
            mwt.append((msn.tags.all(), msn.manifest))
        return mwt


class ConditionManager(models.Manager):
    def for_deletion(self):
        return self.annotate(
            # not linked to any sub manifest pkg info
            submanifestpkginfo_count=Count("submanifestpkginfo")
        ).filter(submanifestpkginfo_count=0)


class Condition(models.Model):
    name = models.CharField(max_length=256, unique=True)
    predicate = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ConditionManager()

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("monolith:condition", args=(self.pk,))

    def can_be_deleted(self):
        return not self.submanifestpkginfo_set.count()

    def manifests(self):
        return Manifest.objects.distinct().filter(
            manifestsubmanifest__sub_manifest__submanifestpkginfo__condition=self
        )

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "predicate": self.predicate,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        })
        return d


class SubManifestPkgInfo(models.Model):
    sub_manifest = models.ForeignKey(SubManifest, on_delete=models.CASCADE)
    key = models.CharField(max_length=32, choices=SUB_MANIFEST_PKG_INFO_KEY_CHOICES)
    pkg_info_name = models.ForeignKey(PkgInfoName, on_delete=models.PROTECT)
    featured_item = models.BooleanField(default=False)
    condition = models.ForeignKey(Condition, on_delete=models.PROTECT, null=True, blank=True)
    options = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('pkg_info_name',)
        unique_together = (('sub_manifest', 'pkg_info_name'),)

    def get_absolute_url(self):
        return "{}#smp_{}".format(reverse('monolith:sub_manifest', args=(self.sub_manifest.pk,)), self.pk)

    def get_name(self):
        return self.pkg_info_name.name

    # options

    @cached_property
    def excluded_tags(self):
        excluded_tag_names = self.options.get("excluded_tags")
        if not excluded_tag_names:
            return []
        return Tag.objects.select_related("meta_business_unit", "taxonomy").filter(name__in=excluded_tag_names)

    @cached_property
    def tag_shards(self):
        tag_shards = self.options.get("shards", {}).get("tags")
        if not tag_shards:
            return []
        tags = (
            Tag.objects.select_related("meta_business_unit", "taxonomy")
                       .filter(name__in=tag_shards.keys())
                       .order_by("name")
        )
        return [{"tag": tag, "shard": tag_shards[tag.name]} for tag in tags]

    @property
    def default_shard(self):
        return self.options.get("shards", {}).get("default", 100)

    @property
    def shard_modulo(self):
        return self.options.get("shards", {}).get("modulo", 100)


def attachment_path(instance, filename):
    # TODO overflow ?
    return 'monolith/sub_manifests/{0:08d}/{1}/{2}_{3:04d}'.format(
        instance.sub_manifest.id,
        instance.type,
        instance.name,
        instance.version
    )


class Manifest(models.Model):
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, on_delete=models.PROTECT)
    name = models.CharField(max_length=256, unique=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name', 'meta_business_unit__name',)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('monolith:manifest', args=(self.pk,))

    def bump_version(self):
        self.version = F("version") + 1
        self.save()

    def catalogs(self, tags=None):
        if tags is None:
            tags = []
        return [mc.catalog
                for mc in (self.manifestcatalog_set
                               .distinct()
                               .select_related("catalog__repository")
                               .filter(Q(tags__isnull=True) | Q(tags__in=tags)))]

    def sub_manifests(self, tags=None):
        if tags is None:
            tags = []
        return [msm.sub_manifest
                for msm in (self.manifestsubmanifest_set
                                .distinct()
                                .select_related("sub_manifest")
                                .filter(Q(tags__isnull=True) | Q(tags__in=tags)))]

    def sub_manifest(self, sm_id, tags=None):
        if tags is None:
            tags = []
        try:
            msm = (self.manifestsubmanifest_set
                       .distinct()
                       .select_related("sub_manifest")
                       .filter(Q(tags__isnull=True) | Q(tags__in=tags))
                       .get(sub_manifest__id=sm_id))
        except ManifestSubManifest.DoesNotExist:
            pass
        else:
            return msm.sub_manifest

    def enrollment_packages(self, tags=None):
        # Find the existing enrollment packages for a given set of tags.
        # For each builder, we select the enrollment package whose tags
        # are a subset of the machine tags.
        # In case of conflicts, we return the first builder found.
        tags = set(tags or [])
        d = {}
        for ep in (self.manifestenrollmentpackage_set
                       .prefetch_related("tags")
                       .filter(builder__in=monolith_conf.enrollment_package_builders.keys())
                       .filter(Q(tags__isnull=True) | Q(tags__in=tags))
                       .order_by("id")):
            if ep.tag_set.issubset(tags):
                found_ep = d.get(ep.builder)
                if found_ep:
                    if len(found_ep.tag_set) < len(ep.tag_set):
                        d[ep.builder] = ep
                    elif len(found_ep.tag_set) == len(ep.tag_set):
                        # TODO: conflict!
                        logger.error("Manifest %s builder %s mep conflict for machine tags %s",
                                     self.id, ep.builder, ", ".join(str(t) for t in tags))
                else:
                    d[ep.builder] = ep
        return d

    def _pkginfos_with_deps_and_updates(self, tags):
        """PkgInfos linked to a manifest for a given set of tags"""
        kwargs = {"manifest_pk": self.pk}
        if tags:
            m2mt_filter = "OR m2mt.tag_id in %(tag_pks)s"
            kwargs["tag_pks"] = tuple(t.pk for t in tags)
        else:
            m2mt_filter = ""
        query = (
            "WITH RECURSIVE pkginfos_with_deps_and_updates AS ( "

            "SELECT pi.id pk,"
            "pi.repository_id repository_pk,"
            "pi.version version,"
            "pi.file file_name,"
            "pi.data->>'installer_item_location' installer_item_location,"
            "pi.data->>'uninstaller_item_location' uninstaller_item_location,"
            "pi.data->>'icon_name' icon_name,"
            "pn.id name_pk,"
            "pn.name name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "JOIN monolith_submanifestpkginfo sm ON (pn.id=sm.pkg_info_name_id) "
            "JOIN monolith_manifestsubmanifest ms ON (sm.sub_manifest_id=ms.sub_manifest_id) "
            "LEFT JOIN monolith_manifestsubmanifest_tags m2mt ON (ms.id=m2mt.manifestsubmanifest_id) "
            "WHERE ms.manifest_id = %(manifest_pk)s "
            f"AND (m2mt.tag_id IS NULL {m2mt_filter}) "

            "UNION "

            "SELECT pi.id,"
            "pi.repository_id,"
            "pi.version,"
            "pi.file,"
            "pi.data->>'installer_item_location',"
            "pi.data->>'uninstaller_item_location',"
            "pi.data->>'icon_name',"
            "pn.id,"
            "pn.name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_requires pr ON (pr.pkginfoname_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_update_for pu ON (pu.pkginfo_id=pi.id) "
            "JOIN pkginfos_with_deps_and_updates rec ON (pr.pkginfo_id=rec.pk OR pu.pkginfoname_id=rec.name_pk) "

            ") "

            "SELECT pk,"
            "repository_pk,"
            "version,"
            "file_name,"
            "installer_item_location,"
            "uninstaller_item_location,"
            "icon_name,"
            "name "
            "from pkginfos_with_deps_and_updates "
            "JOIN monolith_pkginfo_catalogs pc ON (pk=pc.pkginfo_id) "
            "JOIN monolith_manifestcatalog mc ON (pc.catalog_id=mc.catalog_id) "
            "LEFT JOIN monolith_manifestcatalog_tags m2mt ON (mc.id=m2mt.manifestcatalog_id) "
            "WHERE mc.manifest_id = %(manifest_pk)s "
            f"AND (m2mt.tag_id IS NULL {m2mt_filter});"
        )
        cursor = connection.cursor()
        cursor.execute(query, kwargs)
        for row in cursor.fetchall():
            yield CachedPkgInfo(*row)

    def _enrollment_packages_pkginfo_deps(self, tags):
        """PkgInfos that enrollment packages require, with their dependencies"""
        package_names = tuple(chain.from_iterable(
            ep.get_requires()
            for ep in self.enrollment_packages(tags).values()
        ))
        if not package_names:
            return
        kwargs = {
            "manifest_pk": self.pk,
            "package_names": package_names,
        }
        if tags:
            m2mt_filter = "OR m2mt.tag_id in %(tag_pks)s"
            kwargs["tag_pks"] = tuple(t.pk for t in tags)
        else:
            m2mt_filter = ""
        query = (
            "WITH RECURSIVE pkginfos_with_deps_and_updates AS ( "

            "SELECT pi.id pk,"
            "pi.repository_id repository_pk,"
            "pi.version version,"
            "pi.file file_name,"
            "pi.data->>'installer_item_location' installer_item_location,"
            "pi.data->>'uninstaller_item_location' uninstaller_item_location,"
            "pi.data->>'icon_name' icon_name,"
            "pn.id name_pk,"
            "pn.name name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "WHERE pn.name in %(package_names)s "

            "UNION "

            "SELECT pi.id,"
            "pi.repository_id,"
            "pi.version,"
            "pi.file,"
            "pi.data->>'installer_item_location',"
            "pi.data->>'uninstaller_item_location',"
            "pi.data->>'icon_name',"
            "pn.id,"
            "pn.name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_requires pr ON (pr.pkginfoname_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_update_for pu ON (pu.pkginfo_id=pi.id) "
            "JOIN pkginfos_with_deps_and_updates rec ON (pr.pkginfo_id=rec.pk OR pu.pkginfoname_id=rec.name_pk) "

            ") "

            "SELECT pk,"
            "repository_pk,"
            "version,"
            "file_name,"
            "installer_item_location,"
            "uninstaller_item_location,"
            "icon_name,"
            "name "
            "from pkginfos_with_deps_and_updates "
            "JOIN monolith_pkginfo_catalogs pc ON (pk=pc.pkginfo_id) "
            "JOIN monolith_manifestcatalog mc ON (pc.catalog_id=mc.catalog_id) "
            "LEFT JOIN monolith_manifestcatalog_tags m2mt ON (mc.id=m2mt.manifestcatalog_id) "
            "WHERE mc.manifest_id = &(manifest_pk)s "
            f"AND (m2mt.tag_id IS NULL {m2mt_filter});"
        )
        cursor = connection.cursor()
        cursor.execute(query, kwargs)
        for row in cursor.fetchall():
            yield CachedPkgInfo(*row)

    def get_pkginfo_for_cache(self, tags, pk):
        for cached_pkginfo in chain(self._pkginfos_with_deps_and_updates(tags),
                                    self._enrollment_packages_pkginfo_deps(tags)):
            if cached_pkginfo.pk == pk:
                return cached_pkginfo

    # the manifest catalog - for a given set of tags

    def get_catalog_munki_name(self):
        return build_munki_name("manifest_catalog", self.pk, self.name)

    def build_catalog(self, tags=None):
        pkginfo_list = []

        # the repository catalogs pkginfos
        for pkginfo in (PkgInfo.objects.distinct()
                                       .select_related("name")
                                       .filter(archived_at__isnull=True,
                                               catalogs__in=self.catalogs(tags))):
            pkginfo_list.append(pkginfo.get_pkg_info())

        # the enrollment packages

        # add the unique selected enrollment package in scope for each builder
        in_scope_mep_builders = []
        for builder, enrollment_package in self.enrollment_packages(tags).items():
            in_scope_mep_builders.append(builder)
            pkginfo_list.append(enrollment_package.get_pkg_info())

        # add all the enrollment packages, for the builders not in scope, to allow removal
        not_in_scope_mep_qs = self.manifestenrollmentpackage_set.all()
        if in_scope_mep_builders:
            not_in_scope_mep_qs = not_in_scope_mep_qs.exclude(builder__in=in_scope_mep_builders)
        for not_in_scope_mep in not_in_scope_mep_qs:
            pkginfo_list.append(not_in_scope_mep.get_pkg_info())

        return pkginfo_list

    def serialize_icon_hashes(self, tags):
        icon_hashes = {}
        for catalog in self.catalogs(tags):
            icon_hashes.update(catalog.repository.icon_hashes)
        return plistlib.dumps(icon_hashes)

    def serialize_client_resources(self, tags):
        client_resources = {}
        for catalog in self.catalogs(tags):
            repository_pk = catalog.repository.pk
            for name in catalog.repository.client_resources:
                client_resources[name] = repository_pk
        return client_resources

    # the manifest

    def build(self, tags):
        data = {'catalogs': [self.get_catalog_munki_name()],
                'included_manifests': []}

        # include the sub manifests
        for sm in self.sub_manifests(tags):
            data['included_manifests'].append(sm.get_munki_name())

        # loop on the configured enrollment package builders
        enrollment_packages = self.enrollment_packages(tags)
        for mep in self.manifestenrollmentpackage_set.all():
            mep_name = mep.get_name()
            if mep.builder in enrollment_packages:
                managed_installs = data.setdefault('managed_installs', [])
                if mep_name not in managed_installs:
                    managed_installs.append(mep_name)
            else:
                managed_uninstalls = data.setdefault('managed_uninstalls', [])
                if mep_name not in managed_uninstalls:
                    managed_uninstalls.append(mep_name)

        return data

    def serialize(self, tags):
        return plistlib.dumps(self.build(tags))

    # events

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        if not isinstance(self.version, int):
            # version was updated with a CombinedExpression
            # it needs to be fetched from the DB for the JSON serialization
            self.refresh_from_db()
        d.update({
            "meta_business_unit": self.meta_business_unit.serialize_for_event(keys_only=True),
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        })
        return d


class ManifestCatalog(models.Model):
    manifest = models.ForeignKey(Manifest, on_delete=models.CASCADE)
    catalog = models.ForeignKey(Catalog, on_delete=models.PROTECT)
    tags = models.ManyToManyField(Tag)

    class Meta:
        unique_together = (("manifest", "catalog"),)
        ordering = ('catalog__name',)


class ManifestSubManifest(models.Model):
    manifest = models.ForeignKey(Manifest, on_delete=models.CASCADE)
    sub_manifest = models.ForeignKey(SubManifest, on_delete=models.PROTECT)
    tags = models.ManyToManyField(Tag)


def enrollment_package_path(instance, filename):
    # TODO overflow ?
    return 'monolith/manifests/{0:08d}/enrollment_packages/{1}'.format(
        instance.manifest.id,
        filename
    )


class ManifestEnrollmentPackage(models.Model):
    manifest = models.ForeignKey(Manifest, on_delete=models.CASCADE)
    tags = models.ManyToManyField(Tag)

    builder = models.CharField(max_length=256)
    enrollment_pk = models.PositiveIntegerField(null=True)

    file = models.FileField(upload_to=enrollment_package_path, blank=True)
    pkg_info = models.JSONField(blank=True, null=True)
    version = models.PositiveSmallIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def delete(self, *args, **kwargs):
        delete_enrollment = kwargs.pop("delete_enrollment", True)
        self.file.delete(save=False)
        enrollment = self.get_enrollment()
        super().delete(*args, **kwargs)
        if delete_enrollment and enrollment:
            enrollment.delete()

    def get_installer_item_filename(self):
        return "{}.pkg".format(slugify("{} pk{} v{}".format(self.get_name(),
                                                            self.id,
                                                            self.version)))

    @cached_property
    def builder_class(self):
        return monolith_conf.enrollment_package_builders[self.builder]["class"]

    def get_name(self):
        return self.builder_class.name

    def get_requires(self):
        return monolith_conf.enrollment_package_builders[self.builder]["requires"]

    def get_pkg_info(self):
        pkg_info = self.pkg_info.copy()
        name = self.get_name()
        pkg_info["installer_item_location"] = build_munki_name("enrollment_pkg", self.id, name, "pkg")
        pkg_info["icon_name"] = build_munki_name("enrollment_pkg_icon", self.id, name, "png")
        return pkg_info

    @cached_property
    def tag_set(self):
        return set(self.tags.all())

    def get_enrollment(self):
        try:
            enrollment_model = self.builder_class.form.Meta.model
            return enrollment_model.objects.get(pk=self.enrollment_pk)
        except (AttributeError, ObjectDoesNotExist):
            pass

    def enrollment_update_callback(self):
        self.version = F("version") + 1
        self.save()
        self.refresh_from_db()
        build_manifest_enrollment_package(self)
        self.manifest.bump_version()

    def get_description_for_enrollment(self):
        return "Monolith manifest: {}".format(self.manifest)

    def get_absolute_url(self):
        return "{}#mep_{}".format(reverse("monolith:manifest", args=(self.manifest.pk,)), self.pk)

    def serialize_for_event(self):
        """used for the enrollment secret verification events, via the enrollment"""
        return {"monolith_manifest_enrollment_package": {"pk": self.pk,
                                                         "manifest": {"pk": self.manifest.pk,
                                                                      "name": str(self.manifest)}}}


# Cache server


class CacheServerManager(models.Manager):
    def get_current_for_manifest(self, manifest, max_age):
        min_updated_at = timezone.now() - timedelta(seconds=max_age)
        return self.filter(manifest=manifest,
                           updated_at__gte=min_updated_at)


class CacheServer(models.Model):
    name = models.CharField(max_length=256)
    manifest = models.ForeignKey(Manifest, on_delete=models.CASCADE)
    public_ip_address = models.GenericIPAddressField()
    base_url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CacheServerManager()

    class Meta:
        unique_together = (("name", "manifest"),)

    def get_cache_url(self, url):
        """Build the cache url to redirect to from the repo url

        Apply the scheme and netloc from the cache server base url to the
        repository url.
        """
        p_url = urllib.parse.urlparse(url)
        p_base_url = urllib.parse.urlparse(self.base_url)
        p_url = p_url._replace(scheme=p_base_url.scheme,
                               netloc=p_base_url.netloc)
        return p_url.geturl()

    def serialize(self):
        return {"name": self.name,
                "manifest": {"id": self.manifest.id,
                             "name": str(self.manifest)},
                "public_ip_address": self.public_ip_address,
                "base_url": self.base_url}


# Enrollment


class Enrollment(BaseEnrollment):
    manifest = models.ForeignKey(Manifest, on_delete=models.CASCADE)

    def get_description_for_distributor(self):
        return "Monolith manifest {}".format(self.manifest)

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict.update({"manifest": {"pk": self.manifest.pk,
                                             "name": str(self.manifest)}})
        return enrollment_dict

    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("monolith:manifest", args=(self.manifest.pk,)), self.pk)


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("enrollment", "serial_number")
