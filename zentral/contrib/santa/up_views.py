import logging
from uuid import UUID
from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import View
from realms.up_views import UPLoginRequiredMixin, UPTemplateView
from zentral.contrib.inventory.models import MetaMachine
from .ballot_box import BallotBox, DuplicateVoteError
from .forms import test_sha256
from .models import Target


logger = logging.getLogger("zentral.contrib.santa.up_views")


EVENT_TARGET_IDENTIFIER_KEY = "_up_santa_etid"
MACHINE_ID_SESSION_KEY = "_up_santa_mid"


class EventDetailView(UPLoginRequiredMixin, View):
    def abort(self, err_msg):
        logger.error(err_msg)
        raise SuspiciousOperation(err_msg)

    def get(self, request, *args, **kwargs):
        file_identifier = request.GET.get("fid")
        if not file_identifier:
            self.abort("Empty file identifier")
        if not test_sha256(file_identifier):
            self.abort("Invalid file identifier")
        request.session[EVENT_TARGET_IDENTIFIER_KEY] = file_identifier
        bundle_or_file_identifier = request.GET.get("bofid")
        if not bundle_or_file_identifier:
            self.abort("Empty bundle or file identifier")
        if not test_sha256(bundle_or_file_identifier):
            self.abort("Invalid bundle or file identifier")
        try:
            mid = str(UUID(request.GET.get("mid")))
        except (ValueError, TypeError):
            logger.error("Could not get machine ID from GET parameters")
        else:
            request.session[MACHINE_ID_SESSION_KEY] = str(mid)
        if file_identifier == bundle_or_file_identifier:
            identifier = file_identifier
            target_type = Target.Type.BINARY
        else:
            identifier = bundle_or_file_identifier
            target_type = Target.Type.BUNDLE
        return redirect("realms_public:santa_up:target",
                        realm_pk=self.realm.pk,
                        type=target_type.value.lower(),
                        identifier=identifier)


class TargetDetailView(UPTemplateView):
    template_name = "user_portal/santa_target_detail.html"

    def dispatch(self, request, *args, **kwargs):
        target_type = Target.Type(kwargs["type"].upper())
        target_identifier = kwargs["identifier"]
        self.target = get_object_or_404(Target, type=target_type, identifier=target_identifier)
        try:
            self.current_machine_id = UUID(request.session.get(MACHINE_ID_SESSION_KEY))
        except (ValueError, TypeError):
            self.current_machine_id = None
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["machines"] = []
        ctx["target"] = self.target
        ballot_box = BallotBox.for_realm_user(self.target, self.realm_user, lock_target=False)
        for em, last_seen in ballot_box.voter.enrolled_machines:
            mm = MetaMachine(em.serial_number)
            if em.hardware_uuid == self.current_machine_id:
                ctx["current_machine"] = mm
                ctx["current_configuration"] = em.enrollment.configuration
            ctx["machines"].append(mm)
        ctx["target_info"] = ballot_box.target_info()
        ctx["publisher_info"] = ballot_box.publisher_info()
        ctx["ballot_box"] = ballot_box.best_ballot_box()
        if ctx["ballot_box"]:
            ctx["states"] = sorted(
                ctx["ballot_box"].target_states.items(),
                key=lambda t: (t[0].name, t[0].pk)
            )
            ctx["existing_ballot"] = ctx["ballot_box"].existing_ballot
            ctx["existing_votes"] = sorted(
                ctx["ballot_box"].existing_votes,
                key=lambda t: (t[0].name, t[0].pk)
            )
        return ctx

    def post(self, request, *args, **kwargs):
        try:
            yes_vote = request.POST["yes_vote"]
            assert yes_vote in ("oui", "non")
        except (AssertionError, KeyError):
            messages.error(request, "Invalid request")
        else:
            try:
                event_target = Target.objects.get(
                    type=Target.Type.BINARY,
                    identifier=request.session[EVENT_TARGET_IDENTIFIER_KEY]
                )
            except Exception:
                logger.error("Could not find event target in DB")
                event_target = None
            ballot_box = BallotBox.for_realm_user(self.target, self.realm_user, lock_target=False)
            try:
                ballot_box.best_ballot_box(lock_target=True).cast_default_votes(yes_vote == "oui", event_target)
            except DuplicateVoteError:
                messages.error(request, "You cannot cast the same ballot twice")
            else:
                messages.info(request, "Your ballot has been cast")
        return redirect("realms_public:santa_up:target",
                        realm_pk=self.realm.pk,
                        type=Target.Type(self.target.type).value.lower(),
                        identifier=self.target.identifier)
