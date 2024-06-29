import json
import logging
from django.db import IntegrityError, transaction
from django.http import HttpResponse, JsonResponse
from django.views.generic import View
from accounts.models import APIToken
from zentral.utils.http import basic_auth_username_and_password_from_request
from .models import Lock, State, StateVersion


logger = logging.getLogger("zentral.core.terraform.api_views")


MAX_VERSIONS_PER_STATE = 3


class BackendBaseView(View):
    def dispatch_extra(self):
        return

    def create_state_if_missing(self):
        if self.state:
            return
        if not self.user.has_perm("terraform.add_state"):
            return HttpResponse("Forbidden", status=403)
        self.state = State.objects.create(
            slug=self.state_slug,
            created_by=self.user,
            created_by_username=self.user.username,
        )

    def dispatch(self, request, *args, **kwargs):
        try:
            username, password = basic_auth_username_and_password_from_request(self.request)
        except ValueError as e:
            logger.error(str(e), extra={'request': self.request})
            return HttpResponse('Unauthorized', status=401)
        err_msg = None
        try:
            token = APIToken.objects.get_with_key(password.decode("utf-8"))
            assert token.user.username == username.decode("utf-8")
        except APIToken.DoesNotExist:
            err_msg = 'Bad credentials'
        except AssertionError:
            err_msg = 'Bad username'
        if err_msg:
            logger.error(err_msg, extra={'request': self.request})
            return HttpResponse(err_msg, status=401)
        if not token.user.has_module_perms("terraform"):
            logger.error("User has no module permission", extra={'request': self.request})
            return HttpResponse("Forbidden", status=403)
        self.user = token.user
        self.state_slug = kwargs["slug"]
        try:
            self.state = State.objects.select_for_update().get(slug=self.state_slug)
        except State.DoesNotExist:
            self.state = None
        response = self.dispatch_extra()
        if response:
            return response
        return super().dispatch(request, *args, **kwargs)


class BackendStateView(BackendBaseView):
    def get(self, request, *args, **kwargs):
        logger.info("State %s, GET", self.state_slug, extra={"request": request})
        if not self.user.has_perm("terraform.view_state"):
            return HttpResponse("Forbidden", status=403)
        if not self.state:
            return HttpResponse("State not found", status=404)
        state_version = self.state.stateversion_set.order_by("-pk").first()
        if not state_version:
            return HttpResponse("State version not found", status=404)
        return HttpResponse(state_version.get_data(), status=200)

    def post(self, request, *args, **kwargs):
        lock_uid = request.GET.get("ID")
        logger.info("State %s, lock %s, PUT", self.state_slug, lock_uid or "-", extra={'request': self.request})
        response = self.create_state_if_missing()
        if response:
            return response
        if not self.user.has_perm("terraform.change_state"):
            return HttpResponse("Forbidden", status=403)

        # lock verification
        try:
            lock = self.state.lock
        except Lock.DoesNotExist:
            if lock_uid:
                logger.warning("State %s, lock %s, PUT, state not locked", self.state_slug, lock_uid,
                               extra={'request': self.request})
        else:
            if lock_uid and lock_uid != lock.uid:
                logger.error("State %s, lock %s, PUT, conflict with lock %s",
                             self.state_slug, lock_uid, lock.uid)
                return HttpResponse("Bad lock ID", status=409)
            elif not lock_uid:
                logger.error("State %s, lock -, PUT, lock UID required", self.state_slug,
                             extra={'request': self.request})
                return HttpResponse("Lock ID required", status=409)

        state_version = StateVersion.objects.create(
            state=self.state,
            created_by=self.user,
            created_by_username=self.user.username,
        )
        state_version.set_data(request.body)
        state_version.save()
        sv_ids_to_delete = (
            self.state.stateversion_set.order_by("-pk")
                      .values_list('pk', flat=True)
        )[MAX_VERSIONS_PER_STATE:]
        StateVersion.objects.filter(id__in=sv_ids_to_delete).delete()
        return HttpResponse("OK")

    def delete(self, request, *args, **kwargs):
        logger.info("State %s, DELETE", self.state_slug, extra={'request': self.request})
        if not self.user.has_perm("terraform.delete_state"):
            return HttpResponse("Forbidden", status=403)
        if self.state:
            self.state.delete()
        else:
            logger.warning("State %s, DELETE, unknown state", self.state_slug, extra={'request': self.request})
        return HttpResponse("OK")


class BackendLockView(BackendBaseView):
    def dispatch_extra(self):
        if self.request.method == "DELETE":
            required_permission = "terraform.delete_state"
        else:
            required_permission = "terraform.change_state"
        if not self.user.has_perm(required_permission):
            return HttpResponse("Forbidden", status=403)
        try:
            self.lock_info = json.load(self.request)
            self.lock_uid = self.lock_info["ID"]
        except Exception:
            if self.request.method == "DELETE":
                # it seems that Terraform sometimes doesn't send us the lock ID
                logger.warning("State %s, UNLOCK without Lock ID", self.state_slug, extra={'request': self.request})
                self.lock_info = None
                self.lock_uid = None
            else:
                logger.exception("State %s, could not load lock request body", extra={'request': self.request})
                return HttpResponse("Bad request", status=400)

    def post(self, request, *args, **kwargs):
        logger.info("State %s, LOCK %s", self.state_slug, self.lock_uid, extra={'request': self.request})
        response = self.create_state_if_missing()
        if response:
            return response
        status = 200
        with transaction.atomic():
            try:
                lock = Lock.objects.create(
                    state=self.state,
                    uid=self.lock_uid,
                    info=self.lock_info,
                    created_by=self.user,
                    created_by_username=self.user.username,
                )
            except IntegrityError:
                status = 409
        if status == 409:
            self.state.refresh_from_db()
            lock = self.state.lock
            logger.error("State %s, LOCK %s, conflict with lock %s", self.state_slug, self.lock_uid, lock,
                         extra={'request': self.request})
        return JsonResponse(lock.info, status=status)

    def delete(self, request, *args, **kwargs):
        logger.info("State %s, UNLOCK %s", self.state_slug, self.lock_uid or "-", extra={'request': self.request})
        qs = Lock.objects.filter(state__slug=self.state_slug)
        if self.lock_uid:
            qs = qs.filter(uid=self.lock_uid)
        deleted_lock_count, _ = qs.delete()
        if deleted_lock_count != 1:
            logger.warning("State %s, UNLOCK %s, unexpected deleted lock count: %s",
                           self.state_slug, self.lock_uid or "-", deleted_lock_count,
                           extra={'request': self.request})
        return HttpResponse("OK", status=200)
