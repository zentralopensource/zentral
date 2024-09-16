import logging
import math
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView
from zentral.utils.views import UserPaginationMixin
from zentral.contrib.santa.ballot_box import BallotBox, DuplicateVoteError, VotingNotAllowedError
from zentral.contrib.santa.forms import AdminVoteForm, BallotSearchForm
from zentral.contrib.santa.models import Target


logger = logging.getLogger('zentral.contrib.santa.views.ballots')


class BallotsView(PermissionRequiredMixin, UserPaginationMixin, TemplateView):
    permission_required = "santa.view_ballot"
    template_name = "santa/ballots.html"

    def dispatch(self, request, *args, **kwargs):
        self.form = BallotSearchForm(request.GET)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form

        # current page
        try:
            page = int(self.request.GET.get("page", 1))
        except Exception:
            page = 1
        page = max(1, page)
        limit = self.get_paginate_by()
        offset = (page - 1) * limit

        ctx["ballots"] = self.form.results(self.request.user.username, self.request.user.email, offset, limit)

        # total
        try:
            total = ctx["ballots"][0]["full_count"]
        except IndexError:
            total = 0
        ctx["ballot_count"] = total

        # pagination
        ctx["page_num"] = page
        ctx["num_pages"] = math.ceil(total / self.get_paginate_by()) or 1
        if page > 1:
            qd = self.request.GET.copy()
            qd["page"] = page - 1
            ctx["previous_url"] = f"?{qd.urlencode()}"
            qd.pop("page")
            ctx["reset_link"] = f"?{qd.urlencode()}"
        if offset + self.get_paginate_by() < total:
            qd = self.request.GET.copy()
            qd["page"] = page + 1
            ctx["next_url"] = f"?{qd.urlencode()}"

        return ctx


class CastBallotView(PermissionRequiredMixin, TemplateView):
    permission_required = "santa.add_ballot"
    template_name = "santa/ballot_form.html"

    def get_target(self):
        self.target = get_object_or_404(
            Target,
            type=self.request.GET.get("target_type"),
            identifier=self.request.GET.get("target_identifier")
        )

    def get_realm_user(self):
        if not self.request.realm_authentication_session.user:
            logger.error("No realm user found")
            raise PermissionDenied
        self.realm_user = self.request.realm_authentication_session.user

    def get_context_data(self, **kwargs):
        self.get_target()
        self.get_realm_user()
        forms = kwargs.pop("forms", None)
        ctx = super().get_context_data(**kwargs)
        ctx["target"] = self.target
        ballot_box = BallotBox.for_realm_user(self.target, self.realm_user, lock_target=False, all_configurations=True)
        ctx["ballot_box"] = ballot_box
        ctx["allowed_votes"] = ballot_box.get_configurations_allowed_votes()
        ctx["target_info"] = ballot_box.target_info()
        ctx["publisher_info"] = ballot_box.publisher_info()
        ctx["states"] = sorted(
            ctx["ballot_box"].target_states.items(),
            key=lambda t: (t[0].name, t[0].pk)
        )
        ctx["existing_ballot"] = ctx["ballot_box"].existing_ballot
        ctx["existing_votes"] = sorted(
            ctx["ballot_box"].existing_votes,
            key=lambda t: (t[0].name, t[0].pk)
        )
        if forms is None:
            forms = []
            for configuration, allowed_votes in ballot_box.get_configurations_allowed_votes():
                forms.append(AdminVoteForm(configuration=configuration, allowed_votes=allowed_votes))
        ctx["forms"] = forms
        return ctx

    def post(self, request, *args, **kwargs):
        self.get_target()
        self.get_realm_user()
        ballot_box = BallotBox.for_realm_user(self.target, self.realm_user, lock_target=True, all_configurations=True)
        allowed_votes = ballot_box.get_configurations_allowed_votes()
        forms = []
        votes = []
        form_errors = False
        for configuration, allowed_votes in ballot_box.get_configurations_allowed_votes():
            form = AdminVoteForm(request.POST, configuration=configuration, allowed_votes=allowed_votes)
            forms.append(form)
            if not form.is_valid():
                form_errors = True
            else:
                vote = form.get_vote()
                if vote is not None:
                    votes.append(vote)
        if not form_errors:
            if not votes:
                messages.error(request, "Empty ballot")
            else:
                try:
                    ballot_box.cast_votes(votes)
                except DuplicateVoteError:
                    messages.error(request, "You cannot cast the same ballot twice")
                except VotingNotAllowedError:
                    messages.error(request, "The ballot was rejected")
                else:
                    messages.info(request, "Your ballot has been cast")

                    def on_commit_callback():
                        ballot_box.post_events(self.request)

                    transaction.on_commit(on_commit_callback)

                    return redirect(self.target)
        else:
            messages.error(request, "Invalid ballot")
        return self.render_to_response(self.get_context_data(forms=forms))
