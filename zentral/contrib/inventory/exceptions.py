class EnrollmentSecretVerificationFailed(Exception):
    def __init__(self, err_msg, enrollment_secret=None):
        self.err_msg = err_msg
        self.enrollment_secret = enrollment_secret
