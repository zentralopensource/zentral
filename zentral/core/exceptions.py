class ImproperlyConfigured(Exception):
    def __init__(self, message, err_list=None):
        super(ImproperlyConfigured, self).__init__(message, err_list)
        self.message = message
        self.err_list = err_list or []
