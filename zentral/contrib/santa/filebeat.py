from django import forms


class SantaLogInputForm(forms.Form):
    path = forms.CharField(initial="/var/db/santa/santa.log")

    def get_filebeat_input(self):
        return {"type": "log",
                "paths": [self.cleaned_data["path"]]}


inputs = {"santa_log": {"name": "santa.log",
                        "form_class": SantaLogInputForm}}
