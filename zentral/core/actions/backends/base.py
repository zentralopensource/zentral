class BaseAction(object):
    def __init__(self, config_d):
        self.name = config_d.pop("action_name")
        self.config_d = config_d
