class EnrollmentSessionStatusError(Exception):
    def __init__(self, enrollment_session, next_status):
        self.enrollment_session = enrollment_session
        self.next_status = next_status
