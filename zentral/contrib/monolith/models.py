from datetime import datetime
import logging
import os.path
import plistlib
import urllib.parse
from django.contrib.postgres.fields import JSONField
from django.core import signing
from django.db import models, connection
from django.db.models import Q
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.text import slugify
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from .conf import monolith_conf


logger = logging.getLogger("zentral.contrib.monolith.models")


def build_signed_name(model, key):
    from zentral.utils.api_views import API_SECRET
    return signing.dumps({"m": model, "k": key},
                         salt="monolith", key=API_SECRET)


class Catalog(models.Model):
    name = models.CharField(max_length=256, unique=True)
    priority = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ('-archived_at', '-priority', 'name')

    def __str__(self):
        return self.name

    def get_signed_name(self):
        return build_signed_name("catalog", self.id)

    def serialize(self):
        pkginfo_list = []
        for pkginfo in self.pkginfo_set.select_related("name").filter(archived_at__isnull=True):
            pkginfo_list.append(pkginfo.get_signed_pkg_info())
        return plistlib.dumps(pkginfo_list)

    def get_absolute_url(self):
        return reverse("monolith:catalog", args=(self.pk,))

    def get_pkg_info_url(self):
        return "{}?{}".format(reverse("monolith:pkg_infos"),
                              urllib.parse.urlencode({"catalog": self.pk}))

    def can_be_deleted(self):
        return (monolith_conf.repository.manual_catalog_management
                and self.pkginfo_set.filter(archived_at__isnull=True).count() == 0
                and self.manifestcatalog_set.count() == 0)


class PkgInfoCategory(models.Model):
    name = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class PkgInfoName(models.Model):
    name = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

    def active_pkginfos(self):
        return self.pkginfo_set.filter(archived_at__isnull=True)


class PkgInfoManager(models.Manager):
    def alles(self, **kwargs):
        query = (
            "select pn.id, pn.name, pi.id, pi.version, c.id, c.name "
            "from monolith_pkginfoname as pn "
            "join monolith_pkginfo as pi on (pi.name_id = pn.id) "
            "join monolith_pkginfo_catalogs as pc on (pc.pkginfo_id = pi.id) "
            "join monolith_catalog as c on (c.id = pc.catalog_id) "
            "where pi.archived_at is null "
        )
        params = []
        name = kwargs.get("name")
        if name:
            params.append("%{}%".format(connection.ops.prep_for_like_query(name)))
            query = "{} and UPPER(pn.name) LIKE UPPER(%s) ".format(query)
        catalog = kwargs.get("catalog")
        if catalog:
            params.append(catalog.id)
            query = "{} and c.id = %s ".format(query)
        query = (
          "{} and c.archived_at is null "
          "order by pn.name, pn.id, pi.version, pi.id, c.name, c.id"
        ).format(query)
        cursor = connection.cursor()
        cursor.execute(query, params)
        current_pn = current_pn_id = current_pi = current_pi_id = None
        name_c = info_c = 0
        pkg_name_list = []
        for pn_id, name, pi_id, version, c_id, catalog in cursor.fetchall():
            if pi_id != current_pi_id:
                if current_pi is not None:
                    current_pn['pkg_infos'].append(current_pi)
                    info_c += 1
                current_pi_id = pi_id
                current_pi = {'version': None,
                              'catalogs': []}
            current_pi['version'] = version
            current_pi['catalogs'].append(catalog)
            if pn_id != current_pn_id:
                if current_pn is not None:
                    pkg_name_list.append(current_pn)
                    name_c += 1
                current_pn_id = pn_id
                current_pn = {'id': pn_id,
                              'name': name,
                              'pkg_infos': []}
        if current_pi:
            current_pn['pkg_infos'].append(current_pi)
            info_c += 1
        if current_pn:
            pkg_name_list.append(current_pn)
            name_c += 1
        return name_c, info_c, pkg_name_list


class PkgInfo(models.Model):
    name = models.ForeignKey(PkgInfoName)
    version = models.CharField(max_length=256)
    catalogs = models.ManyToManyField(Catalog)
    category = models.ForeignKey(PkgInfoCategory, null=True, blank=True)
    requires = models.ManyToManyField(PkgInfoName, related_name="required_by")
    update_for = models.ManyToManyField(PkgInfoName, related_name="updated_by")
    data = JSONField()
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

    def get_signed_pkg_info(self):
        pkg_info = self.data.copy()
        pkg_info.pop("catalogs", None)
        for attr in ("installer_item_location", "uninstaller_item_loc"):
            loc = pkg_info.pop(attr, None)
            if loc:
                _, ext = os.path.splitext(loc)
                pkg_info[attr] = "{}{}".format(
                    build_signed_name("repository_package", self.id),
                    ext
                )
        return pkg_info

    def get_absolute_url(self):
        return "{}#{}".format(reverse("monolith:pkg_info_name", args=(self.name.id,)), self.pk)


SUB_MANIFEST_PKG_INFO_KEY_CHOICES = (
    ('managed_installs', 'Managed Installs'),
    ('managed_uninstalls', 'Managed Uninstalls'),
    ('optional_installs', 'Optional Installs'),
    ('managed_updates', 'Managed Updates'),
)


class SubManifest(models.Model):
    """Group of pkginfo or attachments (pkgs, cfg profiles, scripts).

    No catalogs except the attachment catalog."""
    meta_business_unit = models.ForeignKey(MetaBusinessUnit,
                                           blank=True, null=True)  # to restrict some sub manifests to a MBU
    name = models.CharField(max_length=256)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('monolith:sub_manifest', args=(self.pk,))

    def has_attachments(self):
        return SubManifestAttachment.objects.filter(sub_manifest=self).count() > 0

    def pkg_info_dict(self):
        d = {'keys': {},
             'total': {'pkginfo': 0}}
        for sma_type in SUB_MANIFEST_ATTACHMENT_TYPES:
            d['total'][sma_type] = 0
        for smpi in self.submanifestpkginfo_set.select_related('pkg_info_name'):
            key_dict = d['keys'].setdefault(smpi.key,
                                            {'key_display': smpi.get_key_display(),
                                             'key_list': []})
            key_dict['key_list'].append((smpi.pkg_info_name.name, smpi))
            d['total']['pkginfo'] += 1
        for sma in SubManifestAttachment.objects.active().filter(sub_manifest=self):
            key_dict = d['keys'].setdefault(sma.key,
                                            {'key_display': sma.get_key_display(),
                                             'key_list': []})
            key_dict['key_list'].append((sma.name, sma))
            d['total'][sma.type] += 1
        for key, key_d in d['keys'].items():
            key_d['key_list'].sort()
        return d

    def get_signed_name(self):
        return build_signed_name("sub_manifest", self.id)

    def get_catalog_signed_name(self):
        return build_signed_name("sub_manifest_catalog", self.id)

    def serialize(self):
        data = {}
        included_names = set([])
        for key, key_d in self.pkg_info_dict()['keys'].items():
            data[key] = [smo.get_name() for _, smo in key_d['key_list']]
            included_names.update(smo.name for _, smo in key_d['key_list'] if isinstance(smo, SubManifestAttachment))
        # force uninstall on the not included attachments
        qs = SubManifestAttachment.objects.filter(sub_manifest=self).exclude(name__in=included_names)
        data.setdefault('managed_uninstalls', []).extend({sma.get_name() for sma in qs})
        return plistlib.dumps(data)

    def serialize_catalog(self):
        pkginfo_list = []
        # have to include trashed attachments for autoremove to work
        # therefore newest() and not active()
        for sma in SubManifestAttachment.objects.newest().filter(sub_manifest=self):
            pkginfo_list.append(sma.get_signed_pkg_info())
        return plistlib.dumps(pkginfo_list)

    def can_be_deleted(self):
        return self.manifestsubmanifest_set.all().count() == 0


class SubManifestPkgInfo(models.Model):
    sub_manifest = models.ForeignKey(SubManifest)
    key = models.CharField(max_length=32, choices=SUB_MANIFEST_PKG_INFO_KEY_CHOICES)
    pkg_info_name = models.ForeignKey(PkgInfoName)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('pkg_info_name',)
        unique_together = (('sub_manifest', 'pkg_info_name'),)

    def get_absolute_url(self):
        return reverse('monolith:sub_manifest', args=(self.sub_manifest.pk,))

    def get_name(self):
        return self.pkg_info_name.name


def attachment_path(instance, filename):
    # TODO overflow ?
    return 'monolith/sub_manifests/{0:08d}/{1}/{2}_{3:04d}'.format(
        instance.sub_manifest.id,
        instance.type,
        instance.name,
        instance.version
    )


SUB_MANIFEST_ATTACHMENT_TYPES = {
    "configuration_profile": {'name': 'configuration profile',
                              'extension': '.mobileconfig'},
    "package": {'name': 'package',
                'extension': '.pkg'},
    "script": {'name': 'script'},
}

SUB_MANIFEST_ATTACHMENT_TYPE_CHOICES = [
    (k, v['name']) for k, v in SUB_MANIFEST_ATTACHMENT_TYPES.items()
]


class SubManifestAttachmentManager(models.Manager):
    def newest(self):
        return self.order_by('name', '-version').distinct('name')

    def active(self):
        return self.newest().filter(trashed_at__isnull=True)

    def trash(self, sub_manifest, name):
        for sma in self.filter(sub_manifest=sub_manifest, name=name):
            sma.mark_as_trashed()


class SubManifestAttachment(models.Model):
    sub_manifest = models.ForeignKey(SubManifest)
    key = models.CharField(max_length=32, choices=SUB_MANIFEST_PKG_INFO_KEY_CHOICES)
    type = models.CharField(max_length=32, choices=SUB_MANIFEST_ATTACHMENT_TYPE_CHOICES)
    name = models.CharField(max_length=256)
    identifier = models.TextField(blank=True, null=True)
    version = models.PositiveSmallIntegerField(default=0)
    file = models.FileField(upload_to=attachment_path, blank=True)
    pkg_info = JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    trashed_at = models.DateTimeField(null=True)

    objects = SubManifestAttachmentManager()

    class Meta:
        unique_together = (('sub_manifest', 'name', 'version'),)

    def get_name(self):
        return "sub manifest {} {} {}".format(self.sub_manifest.id,
                                              self.get_type_display(),
                                              self.name)

    def get_signed_pkg_info(self):
        pkg_info = self.pkg_info.copy()
        pkg_info['name'] = self.get_name()
        if self.type != "script":
            pkg_info['installer_item_location'] = "{}{}".format(
                build_signed_name('sub_manifest_attachement',
                                  [self.sub_manifest.id, self.id]),
                SUB_MANIFEST_ATTACHMENT_TYPES[self.type]['extension']
            )
        return pkg_info

    def mark_as_trashed(self):
        self.trashed_at = datetime.now()
        self.save()


class Manifest(models.Model):
    meta_business_unit = models.OneToOneField(MetaBusinessUnit)

    class Meta:
        ordering = ('meta_business_unit__name',)

    def __str__(self):
        return str(self.meta_business_unit)

    def get_absolute_url(self):
        return reverse('monolith:manifest', args=(self.pk,))

    def catalogs(self, tags=None):
        if tags is None:
            tags = []
        return [mc.catalog
                for mc in (self.manifestcatalog_set
                               .select_related("catalog")
                               .filter(Q(tags__isnull=True) | Q(tags__in=tags)))]

    def catalog(self, c_id, tags=None):
        if tags is None:
            tags = []
        try:
            mc = (self.manifestcatalog_set
                      .select_related("catalog")
                      .filter(Q(tags__isnull=True) | Q(tags__in=tags))
                      .get(catalog__id=c_id))
        except ManifestCatalog.DoesNotExist:
            pass
        else:
            return mc.catalog

    def sub_manifests(self, tags=None):
        if tags is None:
            tags = []
        return [msm.sub_manifest
                for msm in (self.manifestsubmanifest_set
                                .select_related("sub_manifest")
                                .filter(Q(tags__isnull=True) | Q(tags__in=tags)))]

    def sub_manifest(self, sm_id, tags=None):
        if tags is None:
            tags = []
        try:
            msm = (self.manifestsubmanifest_set
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

    def pkginfos_with_deps_and_updates(self, tags=None):
        """PkgInfos linked to a manifest for a given set of tags"""
        if tags:
            m2mt_filter = "OR m2mt.tag_id in ({})".format(",".join(str(int(t.id)) for t in tags))
        else:
            m2mt_filter = ""
        query = (
            "WITH RECURSIVE pkginfos_with_deps_and_updates AS ( "
            "SELECT pi.id as pi_id, pi.version as pi_version, pn.id AS pn_id, pn.name as pn_name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "JOIN monolith_submanifestpkginfo sm ON (pn.id=pkg_info_name_id) "
            "JOIN monolith_manifestsubmanifest ms ON (sm.sub_manifest_id=ms.sub_manifest_id) "
            "LEFT JOIN monolith_manifestsubmanifest_tags m2mt ON (ms.id=m2mt.manifestsubmanifest_id) "
            "WHERE ms.manifest_id = {manifest_id} "
            "AND (m2mt.tag_id IS NULL {m2mt_filter}) "
            "UNION "
            "SELECT pi.id, pi.version, pn.id, pn.name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_requires pr ON (pr.pkginfoname_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_update_for pu ON (pu.pkginfo_id=pi.id) "
            "JOIN pkginfos_with_deps_and_updates rec ON (pr.pkginfo_id=rec.pi_id OR pu.pkginfoname_id=rec.pn_id) "
            ") "
            "SELECT pi_id as id, pi_version as version from pkginfos_with_deps_and_updates "
            "JOIN monolith_pkginfo_catalogs pc ON (pi_id=pc.pkginfo_id) "
            "JOIN monolith_manifestcatalog mc ON (pc.catalog_id=mc.catalog_id) "
            "LEFT JOIN monolith_manifestcatalog_tags m2mt ON (mc.id=m2mt.manifestcatalog_id) "
            "WHERE mc.manifest_id = {manifest_id} "
            "AND (m2mt.tag_id IS NULL {m2mt_filter});"
        ).format(manifest_id=int(self.id), m2mt_filter=m2mt_filter)
        return PkgInfo.objects.raw(query)

    def enrollment_packages_pkginfo_deps(self, tags=None):
        """PkgInfos that enrollment packages are an update for with their dependencies"""
        update_for_list = ",".join(["'{}'".format(ep.get_update_for())
                                    for ep in self.enrollment_packages(tags).values()])
        if tags:
            m2mt_filter = "OR m2mt.tag_id in ({})".format(",".join(str(int(t.id)) for t in tags))
        else:
            m2mt_filter = ""
        query = (
            "WITH RECURSIVE pkginfos_with_deps_and_updates AS ( "
            "SELECT pi.id as pi_id, pi.version as pi_version, pn.id AS pn_id, pn.name as pn_name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "WHERE pn.name in ({update_for_list}) "
            "UNION "
            "SELECT pi.id, pi.version, pn.id, pn.name "
            "FROM monolith_pkginfo pi "
            "JOIN monolith_pkginfoname pn ON (pi.name_id=pn.id) "
            "LEFT JOIN monolith_pkginfo_requires pr ON (pr.pkginfoname_id=pn.id) "
            "JOIN pkginfos_with_deps_and_updates rec ON (pr.pkginfo_id=rec.pi_id) "
            ") "
            "SELECT pi_id as id, pi_version as version from pkginfos_with_deps_and_updates "
            "JOIN monolith_pkginfo_catalogs pc ON (pi_id=pc.pkginfo_id) "
            "JOIN monolith_manifestcatalog mc ON (pc.catalog_id=mc.catalog_id) "
            "LEFT JOIN monolith_manifestcatalog_tags m2mt ON (mc.id=m2mt.manifestcatalog_id) "
            "WHERE mc.manifest_id = {manifest_id} "
            "AND (m2mt.tag_id IS NULL {m2mt_filter});"
        ).format(update_for_list=update_for_list, manifest_id=int(self.id), m2mt_filter=m2mt_filter)
        return PkgInfo.objects.raw(query)

    def get_enrollment_catalog_signed_name(self):
        return build_signed_name("enrollment_catalog", self.meta_business_unit.id)

    def serialize_enrollment_catalog(self, tags):
        # loop on the enrollment packages for the given set of tags.
        pkginfo_list = []
        for enrollment_package in self.enrollment_packages(tags).values():
            pkginfo_list.append(enrollment_package.get_signed_pkg_info())
        return plistlib.dumps(pkginfo_list)

    def serialize(self, tags):
        data = {'catalogs': [c.get_signed_name() for c in self.catalogs(tags)],
                'included_manifests': []}

        # include the sub manifests
        for sm in self.sub_manifests(tags):
            data['included_manifests'].append(sm.get_signed_name())
            if sm.has_attachments():
                # add the sub manifest catalog to make the attachments available.
                # include the catalog even if the attachments are all trashed
                # so that autoremove works.
                data['catalogs'].append(sm.get_catalog_signed_name())

        # add the special catalog for the zentral enrollment packages
        data['catalogs'].append(self.get_enrollment_catalog_signed_name())

        # loop on the configured enrollment package builders
        enrollment_packages = self.enrollment_packages(tags)
        for builder, builder_config in monolith_conf.enrollment_package_builders.items():
            if builder in enrollment_packages:
                key = "managed_installs"
            else:
                # TODO: do not remove munki deps
                key = "managed_uninstalls"
            data.setdefault(key, []).append(builder_config["update_for"])

        return plistlib.dumps(data)


class ManifestCatalog(models.Model):
    manifest = models.ForeignKey(Manifest)
    catalog = models.ForeignKey(Catalog)
    tags = models.ManyToManyField(Tag)

    class Meta:
        ordering = ('-catalog__priority', '-catalog__name')


class ManifestSubManifest(models.Model):
    manifest = models.ForeignKey(Manifest)
    sub_manifest = models.ForeignKey(SubManifest)
    tags = models.ManyToManyField(Tag)


def enrollment_package_path(instance, filename):
    # TODO overflow ?
    return 'monolith/manifests/{0:08d}/enrollment_packages/{1}'.format(
        instance.manifest.id,
        filename
    )


class ManifestEnrollmentPackage(models.Model):
    manifest = models.ForeignKey(Manifest)
    tags = models.ManyToManyField(Tag)
    builder = models.CharField(max_length=256)
    build_kwargs = JSONField('builder parameters')
    file = models.FileField(upload_to=enrollment_package_path, blank=True)
    pkg_info = JSONField(blank=True, null=True)
    version = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_installer_item_filename(self):
        return "{}.pkg".format(slugify("{} pk{} v{}".format(self.get_name(),
                                                            self.id,
                                                            self.version)))

    @cached_property
    def builder_class(self):
        return monolith_conf.enrollment_package_builders[self.builder]["class"]

    def get_name(self):
        return self.builder_class.name

    def get_optional(self):
        return monolith_conf.enrollment_package_builders[self.builder]["optional"]

    def get_update_for(self):
        return monolith_conf.enrollment_package_builders[self.builder]["update_for"]

    def get_signed_pkg_info(self):
        pkg_info = self.pkg_info.copy()
        pkg_info["installer_item_location"] = "{}.pkg".format(build_signed_name("enrollment_pkg", self.id))
        return pkg_info

    @cached_property
    def tag_set(self):
        return set(self.tags.all())
