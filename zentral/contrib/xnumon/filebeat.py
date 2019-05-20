from django import forms


class XnumonLogInputForm(forms.Form):
    path = forms.CharField(initial="/var/log/xnumon.log")

    def get_filebeat_input(self):
        return {"type": "log",
                "paths": [self.cleaned_data["path"]],
                "json": {"keys_under_root": False,
                         "add_error_key": True}}


inputs = {"xnumon_log": {"name": "xnumon.log",
                         "form_class": XnumonLogInputForm}}
