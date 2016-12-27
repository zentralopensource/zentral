from django import forms
from django.contrib.auth.forms import PasswordResetForm, UsernameField
from django.utils.crypto import get_random_string
from .models import User


class AddUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email")
        field_classes = {'username': UsernameField}

    def save(self, request):
        user = super(AddUserForm, self).save(commit=False)
        user.set_password(get_random_string(1024))
        user.save()
        prf = PasswordResetForm({"email": user.email})
        if prf.is_valid():
            prf.save(request=request, use_https=True,
                     email_template_name='registration/invitation_email.html',
                     subject_template_name='registration/invitation_subject.txt')
        return user


class UpdateUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email", "is_superuser")
        field_classes = {'username': UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.username_and_email_editable():
            self.fields["username"].disabled = True
            self.fields["email"].disabled = True
        if not self.instance.is_superuser_editable():
            self.fields["is_superuser"].disabled = True
