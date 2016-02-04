def test_probe_event_type(probe, module_str):
    """Test the probe event type metadata filters.

       Used to find the probes that apply to the events of a module"""
    metadata_filters = probe.get('metadata_filters', [])
    for metadata_filter in metadata_filters:
        event_type_filter_attr = "type"
        event_type_filter_val = metadata_filter.get(event_type_filter_attr, None)
        if not event_type_filter_val or event_type_filter_val.startswith(module_str):
            return True
    return False
