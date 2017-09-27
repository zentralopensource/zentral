from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _


class PasswordNotAlreadyUsedValidator(object):
    def __init__(self, min_unique_passwords=None):
        # min_unique_passwords == None: always a new password
        # min_unique_passwords == 10: password different than the 10 last passwords
        self.min_unique_passwords = min_unique_passwords

    def validate(self, password, user=None):
        if user is None:
            return
        if user.check_password(password):
            raise ValidationError(
               _("Please, pick a new password."),
               code='password_already_used',
               params={'min_unique_passwords': self.min_unique_passwords},
            )
        tested_passwords = 1  # 1 because we have already checked the current one
        for uph in user.userpasswordhistory_set.all().order_by("-id"):
            tested_passwords += 1
            if check_password(password, uph.password):
                raise ValidationError(
                    _("This password has already been used."),
                    code='password_already_used',
                    params={'min_unique_passwords': self.min_unique_passwords},
                )
            if self.min_unique_passwords and self.min_unique_passwords >= tested_passwords:
                break

    def get_help_text(self):
        if self.min_unique_passwords:
            msg = (
                "Your password must be different than the last %(min_unique_passwords)d passwords."
                % {'min_unique_passwords': self.min_unique_passwords}
            )
        else:
            msg = "Your password must not have been used before."
        return _(msg)
