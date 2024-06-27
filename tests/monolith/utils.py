from datetime import datetime
from django.utils.crypto import get_random_string
from tests.munki.utils import force_enrollment as force_munki_enrollment
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.monolith.models import (Catalog, Condition, Enrollment,
                                             Manifest, ManifestCatalog,
                                             ManifestEnrollmentPackage, ManifestSubManifest,
                                             PkgInfo, PkgInfoCategory, PkgInfoName,
                                             SubManifest, SubManifestPkgInfo,
                                             Repository, RepositoryBackend)


CLOUDFRONT_PRIVKEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAKRhksp6Bvp6Iph7vxcAT1FO3p78ek34i3Zjv5p65Yve8SC5ZCef
d3ZfYpTLsq8Bagmv2McYu1BLQcP6808qf5cCAwEAAQJBAJGPOX4EOoO4fUQLaDYE
9zenoGimZ+L9cPl/8J3pr7R/ZcJkXMIj9t7cI1rY/Tk5N2ARBZ/H3NE4Unm7xZJU
lKECIQDXoiGSvGMSB3rLKZYqyAj75O/lsh9TtZRZgF/bUBBScQIhAMMnREkKtr9d
5W7eziXRABOnVdQjPPle1KiHlSaAFmaHAiB70nUW7qixFKx1dzbs8BsAknETZBpL
FkzOrEHfDPWicQIhAKN8I7Jk7U9HY8sLj/sSKVRNnJNIqe3mSZSdcI9+QkXFAiBg
Y5iiw7n52shShyNTBggl3Xp8BILhfrIgGJ6o8jOQwA==
-----END RSA PRIVATE KEY-----"""


def force_repository(
    mbu=None,
    virtual=False,
    secret_access_key=None,
    cloudfront_privkey_pem=None,
    provisioning_uid=None
):
    r = Repository.objects.create(
        provisioning_uid=provisioning_uid,
        name=get_random_string(12),
        meta_business_unit=mbu,
        backend=RepositoryBackend.VIRTUAL if virtual else RepositoryBackend.S3,
        backend_kwargs={},
    )
    if not virtual:
        kwargs = {
            "bucket": get_random_string(12),
            "region_name": "us-east1",
            "prefix": "munki_repo/",
            "access_key_id": get_random_string(20),
            "secret_access_key": secret_access_key or get_random_string(20),
            "signature_version": "s3v4",
            "endpoint_url": None,
        }
        if cloudfront_privkey_pem:
            kwargs["cloudfront_domain"] = get_random_string(8) + ".cloudfront.net"
            kwargs["cloudfront_key_id"] = get_random_string(8)
            kwargs["cloudfront_privkey_pem"] = cloudfront_privkey_pem
        r.set_backend_kwargs(kwargs)
        r.save()
    return r


def force_manifest(mbu=None, name=None):
    if not mbu:
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
    return Manifest.objects.create(meta_business_unit=mbu, name=name or get_random_string(12))


def force_sub_manifest(mbu=None, name=None, description=None, manifest=None, tags=None):
    sm = SubManifest.objects.create(
        name=name or get_random_string(12),
        description=description or get_random_string(12),
        meta_business_unit=mbu,
    )
    if manifest:
        msm = ManifestSubManifest.objects.create(manifest=manifest, sub_manifest=sm)
        if tags:
            msm.tags.set(tags)
    return sm


def force_catalog(name=None, repository=None, manifest=None, tags=None, archived=False):
    if not repository:
        repository = force_repository()
    catalog = Catalog.objects.create(
        repository=repository,
        name=get_random_string(12) if name is None else name,
        archived_at=datetime.utcnow() if archived else None,
    )
    if manifest:
        mc = ManifestCatalog.objects.create(manifest=manifest, catalog=catalog)
        if tags:
            mc.tags.set(tags)
    return catalog


def force_condition(name=None):
    return Condition.objects.create(name=name or get_random_string(12), predicate=get_random_string(12))


def force_category(repository=None, name=None):
    if not repository:
        repository = force_repository()
    return PkgInfoCategory.objects.create(repository=repository, name=name or get_random_string(12))


def force_name(name=None):
    return PkgInfoName.objects.create(name=name or get_random_string(12))


def _force_pkg_info(
    local=True,
    version="1.0",
    archived=False,
    catalog=None,
    sub_manifest=None,
    options=None,
    condition=None,
):
    pkg_info_name = force_name()
    data = {"name": pkg_info_name.name,
            "version": version}
    if catalog is None:
        repository = force_repository(virtual=local)
        catalog = force_catalog(repository=repository)
    pi = PkgInfo.objects.create(
        repository=catalog.repository,
        name=pkg_info_name, version=version, local=local,
        archived_at=datetime.utcnow() if archived else None,
        data=data
    )
    pi.catalogs.add(catalog)
    if sub_manifest:
        options = options or {}
        smpi = SubManifestPkgInfo.objects.create(
            sub_manifest=sub_manifest,
            key="managed_installs",
            pkg_info_name=pkg_info_name,
            condition=condition,
            options=options,
        )
    else:
        smpi = None
    return pkg_info_name, catalog, pi, smpi


def force_pkg_info(local=True, version="1.0", archived=False, catalog=None, sub_manifest=None, options=None):
    _, _, pi, _ = _force_pkg_info(local, version, archived, catalog, sub_manifest, options)
    return pi


def force_sub_manifest_pkg_info(sub_manifest=None, archived=False, condition=None):
    if not sub_manifest:
        manifest = force_manifest()
        sub_manifest = force_sub_manifest(manifest=manifest)
    _, _, _, smpi = _force_pkg_info(sub_manifest=sub_manifest, archived=archived, condition=condition)
    return smpi


def force_enrollment(mbu=None, tag_count=0):
    if not mbu:
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
    enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
    tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(tag_count)]
    if tags:
        enrollment_secret.tags.set(tags)
    return (
        Enrollment.objects.create(manifest=force_manifest(mbu=mbu), secret=enrollment_secret),
        tags
    )


def force_manifest_enrollment_package(manifest=None, tags=None):
    if not manifest:
        manifest = force_manifest()
    munki_enrollment = force_munki_enrollment(meta_business_unit=manifest.meta_business_unit)
    mep = ManifestEnrollmentPackage.objects.create(
        manifest=manifest,
        builder="zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder",
        enrollment_pk=munki_enrollment.pk
    )
    munki_enrollment.distributor = mep
    munki_enrollment.save()
    if not tags:
        tags = []
    mep.tags.set(tags)
    return mep
