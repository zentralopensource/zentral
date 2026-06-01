from django import forms
from django.forms.renderers import TemplatesSetting

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


class SelectMultipleWithDisabledOptions(forms.SelectMultiple):
    """SelectMultiple that renders options in ``disabled_values`` with the
    HTML ``disabled`` attribute. Not a security boundary — the disabled attribute is
    client-side only; the server still has to reject smuggled values.
    """

    def __init__(self, *args, disabled_values=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.disabled_values = set(disabled_values or [])

    def create_option(self, name, value, label, selected, index, subindex=None, attrs=None):
        option = super().create_option(name, value, label, selected, index, subindex, attrs)
        # In Django 4.x+, ``value`` is wrapped in ModelChoiceIteratorValue.
        raw = getattr(value, "value", value)
        if raw in self.disabled_values:
            option["attrs"]["disabled"] = True
        return option


class ZentralFormRenderer(TemplatesSetting):
    form_template_name = "django/forms/div.html"
    formset_template_name = "django/forms/formsets/div.html"
