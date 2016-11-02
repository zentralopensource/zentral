import re
from django import forms
from django.core.validators import RegexValidator
from django.utils.translation import ugettext_lazy as _
from .text import split_comma_separated_quoted_string


validate_sha256 = RegexValidator(
    re.compile('^[a-f0-9]{64}\Z'),
    message=_('Enter a valid sha256.'),
    code='invalid'
)


class CommaSeparatedQuotedStringField(forms.CharField):
    def prepare_value(self, value):
        if isinstance(value, (list, set)):
            words = []
            for w in value:
                if "," in w:
                    w = '"{}"'.format(w)
                words.append(w)
            value = ", ".join(words)
        return value

    def to_python(self, value):
        value = super(CommaSeparatedQuotedStringField, self).to_python(value)
        return split_comma_separated_quoted_string(value)
