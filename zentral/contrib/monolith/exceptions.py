class AttachmentError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)


class RepositoryError(Exception):
    pass
