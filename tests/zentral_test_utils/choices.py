def offered(field):
    """The objects that a model choice field offers: its choices, not its queryset, which validates."""
    return [value.instance for value, _ in field.choices if value]
