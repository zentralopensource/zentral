class OTAEnrollmentSessionStatusError(Exception):
    def __init__(self, ota_enrollment_session, next_status):
        self.ota_enrollment_session = ota_enrollment_session
        self.next_status = next_status
