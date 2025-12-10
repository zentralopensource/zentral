from django import forms
from .text import split_comma_separated_quoted_string
from django.forms.renderers import TemplatesSetting


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


class ZentralFormRenderer(TemplatesSetting):
    form_template_name = "django/forms/div.html"
    formset_template_name = "django/forms/formsets/div.html"
