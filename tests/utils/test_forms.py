from django.test import SimpleTestCase

from zentral.utils.forms import SelectMultipleWithDisabledOptions


class _FakeIteratorValue:
    """Mimics Django's ModelChoiceIteratorValue, which wraps the raw pk and
    exposes it on a ``value`` attribute. The widget has to unwrap it before
    looking up in ``disabled_values``.
    """

    def __init__(self, value):
        self.value = value


class SelectMultipleWithDisabledOptionsTests(SimpleTestCase):
    def test_init_without_disabled_values(self):
        widget = SelectMultipleWithDisabledOptions()
        self.assertEqual(widget.disabled_values, set())

    def test_init_coerces_iterable_to_set(self):
        widget = SelectMultipleWithDisabledOptions(disabled_values=[1, 2, 2, 3])
        self.assertEqual(widget.disabled_values, {1, 2, 3})

    def test_create_option_disables_matching_value(self):
        widget = SelectMultipleWithDisabledOptions(disabled_values={42})
        option = widget.create_option("g", 42, "label", False, 0)
        self.assertTrue(option["attrs"].get("disabled"))

    def test_create_option_leaves_non_matching_value_enabled(self):
        widget = SelectMultipleWithDisabledOptions(disabled_values={42})
        option = widget.create_option("g", 7, "label", False, 0)
        self.assertNotIn("disabled", option["attrs"])

    def test_create_option_unwraps_model_choice_iterator_value(self):
        # Django >= 4.x wraps option values; the widget must unwrap before
        # consulting disabled_values, otherwise nothing ever matches.
        widget = SelectMultipleWithDisabledOptions(disabled_values={42})
        option = widget.create_option("g", _FakeIteratorValue(42), "label", False, 0)
        self.assertTrue(option["attrs"].get("disabled"))

    def test_render_emits_disabled_attribute(self):
        # End-to-end: rendering a select must put ``disabled`` on the right
        # <option>s. ``Select.render`` calls ``create_option`` for each choice,
        # so this is the smallest test that exercises the full path.
        widget = SelectMultipleWithDisabledOptions(disabled_values={2})
        widget.choices = [(1, "one"), (2, "two"), (3, "three")]
        html = widget.render("groups", [])
        self.assertIn('<option value="2" disabled', html)
        self.assertNotIn('<option value="1" disabled', html)
        self.assertNotIn('<option value="3" disabled', html)
