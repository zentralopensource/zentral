from django import forms


class JAMFChangeManagementLogForm(forms.Form):
    path = forms.CharField(initial="/usr/local/jss/logs/JAMFChangeManagement.log")

    def get_filebeat_input(self):
        return {
            "type": "log",
            "paths": [self.cleaned_data["path"]],
            "multiline": {
                "pattern": "^\[",
                "negate": True,
                "match": "after"
            }
        }


class JAMFSoftwareServerLogForm(forms.Form):
    path = forms.CharField(initial="/usr/local/jss/logs/JAMFSoftwareServer.log")

    def get_filebeat_input(self):
        return {
            "type": "log",
            "paths": [self.cleaned_data["path"]],
            "multiline": {
                "pattern": "^2",
                "negate": True,
                "match": "after"
            }
        }


class JSSAccessLogForm(forms.Form):
    path = forms.CharField(initial="/usr/local/jss/logs/JSSAccess.log")

    def get_filebeat_input(self):
        return {
            "type": "log",
            "paths": [self.cleaned_data["path"]]
        }


class ClientLogForm(forms.Form):
    path = forms.CharField(initial="/var/log/jamf.log")

    def get_filebeat_input(self):
        return {
            "type": "log",
            "paths": [self.cleaned_data["path"]],
            "multiline": {
                "pattern": ("^[A-Z][a-z]{2}\s[A-Z][a-z]{2}\s[\s0-9]{2}\s[\s012]?[0-9]:[0-5][0-9]:[0-5][0-9]\s"
                            ".*\s\S+\[[0-9]{1,6}\]:\s.*$"),
                "negate": True,
                "match": "after"
            }
        }


inputs = {
    "jamf_change_management": {
        "name": "JAMFChangeManagement.log",
        "form_class": JAMFChangeManagementLogForm
    },
    "jamf_software_server": {
        "name": "JAMFSoftwareServer.log",
        "form_class": JAMFSoftwareServerLogForm
    },
    "jss_access": {
        "name": "JSSAccess.log",
        "form_class": JSSAccessLogForm
    },
    "client": {
        "name": "jamf.log",
        "form_class": ClientLogForm
    }
}
