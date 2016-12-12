class MockMetaMachine(object):
    def __init__(self, meta_business_unit_id_set, tag_id_set, platform, type, serial_number="YO"):
        self.meta_business_unit_id_set = set(meta_business_unit_id_set)
        self.tag_id_set = set(tag_id_set)
        self.platform = platform
        self.type = type
        self.serial_number = serial_number
        self.has_deb_packages = platform == "LINUX"
