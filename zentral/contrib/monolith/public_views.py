from itertools import chain
import logging
import plistlib
import random
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponse, HttpResponseForbidden, HttpResponseNotFound, HttpResponseRedirect
from django.utils.functional import cached_property
from django.views.generic import View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MachineTag, MetaMachine
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.storage import file_storage_has_signed_urls
from .conf import monolith_conf
from .events import post_monolith_enrollment_event, post_monolith_munki_request
from .models import MunkiNameError, parse_munki_name, CacheServer, EnrolledMachine, ManifestEnrollmentPackage
from .utils import filter_catalog_data, filter_sub_manifest_data


logger = logging.getLogger('zentral.contrib.monolith.public_views')


class MRBaseView(View):
    def post_monolith_munki_request(self, **payload):
        payload["manifest"] = {"id": self.manifest.id,
                               "name": str(self.manifest),
                               "version": self.manifest.version}
        post_monolith_munki_request(self.machine_serial_number, self.user_agent, self.ip, **payload)

    def get_secret(self, request):
        try:
            return request.META["HTTP_AUTHORIZATION"].strip().split()[-1]
        except (AttributeError, IndexError, KeyError):
            raise PermissionDenied("Could not read enrollment secret")

    def get_serial_number(self, request):
        try:
            return request.META["HTTP_X_ZENTRAL_SERIAL_NUMBER"].strip()
        except (AttributeError, KeyError):
            raise PermissionDenied("Missing custom serial number header")

    def get_uuid(self, request):
        try:
            return request.META["HTTP_X_ZENTRAL_UUID"].strip()
        except (AttributeError, KeyError):
            raise PermissionDenied("Missing custom UUID header")

    def enroll_machine(self, request, secret, serial_number):
        uuid = self.get_uuid(request)
        try:
            es_request = verify_enrollment_secret(
                "monolith_enrollment", secret,
                self.user_agent, self.ip, serial_number, uuid
            )
        except EnrollmentSecretVerificationFailed:
            raise PermissionDenied("Enrollment secret verification failed")
        enrollment = es_request.enrollment_secret.monolith_enrollment
        # get or create enrolled machine
        enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.get_or_create(
            enrollment=enrollment,
            serial_number=serial_number,
        )
        if enrolled_machine_created:
            # apply enrollment secret tags
            for tag in es_request.enrollment_secret.tags.all():
                MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)
            post_monolith_enrollment_event(serial_number, self.user_agent, self.ip, {'action': "enrollment"})
        return enrolled_machine

    def get_enrolled_machine_and_tags(self, request):
        secret = self.get_secret(request)
        serial_number = self.get_serial_number(request)
        cache_key = "{}{}".format(secret, serial_number)
        try:
            enrolled_machine, tags = cache.get(cache_key)
        except TypeError:
            try:
                enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__secret",
                                                                           "enrollment__manifest")
                                                           .get(enrollment__secret__secret=secret,
                                                                serial_number=serial_number))
            except EnrolledMachine.DoesNotExist:
                enrolled_machine = self.enroll_machine(request, secret, serial_number)
            machine = MetaMachine(serial_number)
            tags = machine.tags
            cache.set(cache_key, (enrolled_machine, tags), 600)
        return enrolled_machine, tags

    def dispatch(self, request, *args, **kwargs):
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        enrolled_machine, self.tags = self.get_enrolled_machine_and_tags(request)
        self.machine_serial_number = enrolled_machine.serial_number
        self.manifest = enrolled_machine.enrollment.manifest
        return super().dispatch(request, *args, **kwargs)


class MRNameView(MRBaseView):
    def get_request_args(self, name):
        try:
            model, key = parse_munki_name(name)
        except MunkiNameError:
            model = key = None
        return model, key

    def get_cache_key(self, model, key):
        items = ["monolith",
                 self.manifest.pk, self.manifest.version]
        items.extend(sorted(t.id for t in self.tags))
        items.append(model)
        if isinstance(key, list):
            items.extend(key)
        else:
            items.append(key)
        return ".".join(str(i) for i in items)

    def get(self, request, *args, **kwargs):
        name = kwargs["name"]
        event_payload = {"type": self.event_payload_type,
                         "name": name}
        model, key = self.get_request_args(name)
        if model is None or key is None:
            error = True
            response = HttpResponseForbidden("No no no!")
        else:
            cache_key = self.get_cache_key(model, key)
            event_payload.update({
                "subtype": model,
                "cache": {
                    "key": cache_key,
                    "hit": False
                }
            })
            response = self.do_get(model, key, cache_key, event_payload)
            if not response:
                error = True
                response = HttpResponseNotFound("Not found!")
            else:
                error = False
        event_payload["error"] = error
        self.post_monolith_munki_request(**event_payload)
        return response


class MRCatalogView(MRNameView):
    event_payload_type = "catalog"

    def do_get(self, model, key, cache_key, event_payload):
        if model == "manifest_catalog" and key == self.manifest.pk:
            catalog_data = cache.get(cache_key)
            if not isinstance(catalog_data, list):
                catalog_data = self.manifest.build_catalog(self.tags)
                cache.set(cache_key, catalog_data, timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            return HttpResponse(
                plistlib.dumps(
                    filter_catalog_data(
                        catalog_data,
                        self.machine_serial_number,
                        [t.name for t in self.tags]
                    )
                ),
                content_type="application/xml"
            )


class MRManifestView(MRNameView):
    event_payload_type = "manifest"

    def get_request_args(self, name):
        model, key = super().get_request_args(name)
        if model is None or key is None:
            # Not a valid munki name.
            # It is the first request for the main manifest.
            model = "manifest"
            key = self.manifest.id
        return model, key

    def do_get(self, model, key, cache_key, event_payload):
        manifest_data = None
        if model == "manifest":
            manifest_data = cache.get(cache_key)
            if manifest_data is None:
                manifest_data = self.manifest.serialize(self.tags)
                cache.set(cache_key, manifest_data, timeout=None)
            else:
                event_payload["cache"]["hit"] = True
        elif model == "sub_manifest":
            sm_id = key
            event_payload["sub_manifest"] = {"id": sm_id}
            sub_manifest_name = None
            sub_manifest_data = None
            try:
                sub_manifest_name, sub_manifest_data = cache.get(cache_key)
                if not isinstance(sub_manifest_data, dict):  # TODO remove, needed for sm pkg options migration
                    raise ValueError
            except (TypeError, ValueError):
                # verify machine access to sub manifest and respond
                sub_manifest = self.manifest.sub_manifest(sm_id, self.tags)
                if sub_manifest:
                    sub_manifest_name = sub_manifest.name
                    sub_manifest_data = sub_manifest.build()
                # set the cache value, even if sub_manifest_name and sub_manifest_data are None
                cache.set(cache_key, (sub_manifest_name, sub_manifest_data), timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if sub_manifest_name:
                event_payload["sub_manifest"]["name"] = sub_manifest_name
            if sub_manifest_data is not None:
                manifest_data = plistlib.dumps(
                    filter_sub_manifest_data(
                        sub_manifest_data,
                        self.machine_serial_number,
                        [t.name for t in self.tags]
                    )
                )
        if manifest_data:
            return HttpResponse(manifest_data, content_type="application/xml")


class MRPackageView(MRNameView):
    event_payload_type = "package"

    def _get_cache_server(self):
        cache_key = f"monolith.{self.manifest.pk}.cache-servers"
        cache_servers = cache.get(cache_key)
        if cache_servers is None:
            max_age = 10 * 60
            cache_servers = list(CacheServer.objects.get_current_for_manifest(self.manifest, max_age // 2))
            cache.set(cache_key, cache_servers, timeout=max_age // 2)
        if cache_servers:
            try:
                return random.choice([cs for cs in cache_servers if cs.ip == self.ip])
            except IndexError:
                return

    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def do_get(self, model, key, cache_key, event_payload):
        if model == "enrollment_pkg":
            # intercept calls for mbu enrollment packages
            mep_id = key
            event_payload["manifest_enrollment_package"] = {"id": mep_id}
            filename = cache.get(cache_key)
            if filename is None:
                try:
                    mep = ManifestEnrollmentPackage.objects.get(manifest=self.manifest, pk=mep_id)
                except ManifestEnrollmentPackage.DoesNotExist:
                    pass
                else:
                    filename = mep.file.name
                # set the cache value, even if filename is None
                cache.set(cache_key, filename, timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if filename:
                event_payload["manifest_enrollment_package"]["filename"] = filename
                if self._redirect_to_files:
                    return HttpResponseRedirect(default_storage.url(filename))
                else:
                    return FileResponse(default_storage.open(filename))
        elif model == "repository_package":
            pk = key
            event_payload["repository_package"] = {"id": pk}
            pkginfo_name = pkginfo_version = pkginfo_iil = pkginfo_fn = None
            try:
                pkginfo_name, pkginfo_version, pkginfo_iil, pkginfo_fn = cache.get(cache_key)
            except TypeError:
                for pkginfo in chain(self.manifest.pkginfos_with_deps_and_updates(self.tags),
                                     self.manifest.enrollment_packages_pkginfo_deps(self.tags)):
                    if pkginfo.pk == pk:
                        pkginfo_name = pkginfo.name.name
                        pkginfo_version = pkginfo.version
                        if pkginfo.file:
                            pkginfo_fn = pkginfo.file.name
                        else:
                            pkginfo_iil = pkginfo.data.get("installer_item_location")
                        break
                # set the cache value, even if pkginfo_name, pkginfo_version and pkginfo_iil are None
                cache.set(cache_key, (pkginfo_name, pkginfo_version, pkginfo_iil, pkginfo_fn), timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if pkginfo_name is not None:
                event_payload["repository_package"]["name"] = pkginfo_name
            if pkginfo_version is not None:
                event_payload["repository_package"]["version"] = pkginfo_version
            if pkginfo_iil:
                return monolith_conf.repository.make_munki_repository_response(
                    "pkgs", pkginfo_iil, cache_server=self._get_cache_server()
                )
            elif pkginfo_fn:
                if self._redirect_to_files:
                    return HttpResponseRedirect(default_storage.url(pkginfo_fn))
                else:
                    return FileResponse(default_storage.open(pkginfo_fn))
            else:
                # should never happen
                return HttpResponseNotFound("PkgInfo not found!")


class MRRedirectView(MRBaseView):
    section = None

    def get(self, request, *args, **kwargs):
        name = kwargs["name"]
        self.post_monolith_munki_request(type=self.section, name=name)
        return monolith_conf.repository.make_munki_repository_response(self.section, name)
