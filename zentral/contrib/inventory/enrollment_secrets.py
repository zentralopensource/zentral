"""The secret of an enrollment, in the API, in the downloads and on the pages.

Each module registers its request class with pbac.register_view_enrollment_secret(). The view permission of the
enrollment model opens the enrollment. The secret action decides only its secret.
"""
from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework.response import Response
from pbac.engine import engine
from pbac.scoping import visible_rows
from pbac.utils import log_refusal, permitted_pks
from .events import post_enrollment_secret_viewed_event


def enrollments_with_readable_secret(user, request_class, enrollments):
    """Decide the secret of each enrollment in one batch. Return the enrollments with a readable secret.

    A secret left out of a response is a filter: no log (PBAC rule 14).
    """
    enrollments = list(enrollments)
    pks = permitted_pks(user, request_class, enrollments)
    return [enrollment for enrollment in enrollments if enrollment.pk in pks]


def check_enrollment_secret(request, request_class, enrollment):
    """For a download or a page that is the secret, behind the view permission of the enrollment: a 403 if refused.

    The caller posts the event once the secret is in the response.
    """
    pbac_request = request_class(request.user, enrollment)
    engine.authorize_request(pbac_request)
    if not pbac_request.is_authorized:
        log_refusal(request, pbac_request)
        raise PermissionDenied


def enrollment_secret_download(request, request_class, enrollment, build_response):
    """A download that holds the secret: decide, build the response, post the event if the secret is in it.

    A failed build, or the 304 of a conditional request, sends no event.
    """
    check_enrollment_secret(request, request_class, enrollment)
    response = build_response()
    if response.status_code == 200:
        post_enrollment_secret_viewed_event(request, [enrollment], request_class.secret_field,
                                            f"download:{request.resolver_match.url_name}")
    return response


def post_enrollment_secret_viewed_event_on_render(response, request, enrollments, secret_field, where):
    """Post the event once the response is rendered: a failure before it sends no event.

    For a TemplateResponse, a page or a DRF Response. A download is rendered when it is built.
    """
    if enrollments:
        def post_event(_):
            # a callback that returns a value replaces the response
            post_enrollment_secret_viewed_event(request, enrollments, secret_field, where)

        response.add_post_render_callback(post_event)
    return response


def can_read_enrollment_secret(user, request_class, enrollment):
    # a control that the page shows or hides: a filter, which logs nothing
    pbac_request = request_class(user, enrollment)
    engine.authorize_request(pbac_request)
    return pbac_request.is_authorized


def enrollment_pks_with_secret(user, request_class, queryset):
    # the controls of the rows of a page: a filter, which logs nothing
    return set(visible_rows(user, request_class, queryset).values_list("pk", flat=True))


# API


class EnrollmentSecretAPIMixin:
    """For the list and the detail of the enrollments. Their serializer nests an EnrollmentSecretSerializer.

    The view permission of the model opens the enrollments. The secret is decided for each enrollment that a
    response holds, also in the response of a create and of an update: an enrollment without the secret action
    has a null secret. A serializer without these decisions in its context returns no secret.
    """
    secret_request_class = None

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["enrollment_secret_pks"] = getattr(self, "enrollment_secret_pks", set())
        return context

    def readable_secret_enrollments(self, enrollments):
        return enrollments_with_readable_secret(self.request.user, self.secret_request_class, enrollments)

    def secret_pks(self, enrollments):
        return {getattr(enrollment, self.secret_request_class.secret_field).pk for enrollment in enrollments}

    def decide_read_secrets(self, enrollments):
        allowed = self.readable_secret_enrollments(enrollments)
        self.enrollment_secret_pks = self.secret_pks(allowed)
        return allowed

    def post_read_event_on_render(self, response, allowed, where):
        return post_enrollment_secret_viewed_event_on_render(
            response, self.request, allowed, self.secret_request_class.secret_field, where
        )

    def decide_written_secret(self, serializer, where):
        # the response is the data of this serializer, and its nested fields read the context of the root
        allowed = self.readable_secret_enrollments([serializer.instance])
        serializer.context["enrollment_secret_pks"] = self.secret_pks(allowed)
        if allowed:
            # after the audit event of the write, and only if the write is committed
            request = self.request
            secret_field = self.secret_request_class.secret_field
            transaction.on_commit(lambda: post_enrollment_secret_viewed_event(request, allowed, secret_field, where))


class EnrollmentSecretListMixin(EnrollmentSecretAPIMixin):
    def list(self, request, *args, **kwargs):
        secret_field = self.secret_request_class.secret_field
        # the decisions read the secret of each row, and the serializer its tags
        queryset = (self.filter_queryset(self.get_queryset())
                        .select_related(secret_field).prefetch_related(f"{secret_field}__tags"))
        page = self.paginate_queryset(queryset)
        rows = list(page if page is not None else queryset)
        allowed = self.decide_read_secrets(rows)
        serializer = self.get_serializer(rows, many=True)
        if page is not None:
            response = self.get_paginated_response(serializer.data)
        else:
            response = Response(serializer.data)
        return self.post_read_event_on_render(response, allowed, "api_list")

    def perform_create(self, serializer):
        super().perform_create(serializer)
        self.decide_written_secret(serializer, "api_create")


class EnrollmentSecretDetailMixin(EnrollmentSecretAPIMixin):
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        allowed = self.decide_read_secrets([instance])
        response = Response(self.get_serializer(instance).data)
        return self.post_read_event_on_render(response, allowed, "api_detail")

    def perform_update(self, serializer):
        super().perform_update(serializer)
        self.decide_written_secret(serializer, "api_update")
