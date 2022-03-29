from django import forms
from .text import split_comma_separated_quoted_string


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
