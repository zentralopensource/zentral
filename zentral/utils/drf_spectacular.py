def register_enum_name_overrides(**overrides):
    """Merge per-app enum name overrides into drf-spectacular's setting."""
    from drf_spectacular.settings import spectacular_settings
    spectacular_settings.ENUM_NAME_OVERRIDES.update(overrides)
