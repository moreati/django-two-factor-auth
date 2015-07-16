from binascii import unhexlify
from time import time

from django import forms
from django.forms import ModelForm, Form
from django.utils.translation import ugettext_lazy as _

from django_otp.forms import OTPAuthenticationFormMixin
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice
from two_factor.utils import totp_digits

try:
    from otp_yubikey.models import RemoteYubikeyDevice, YubikeyDevice
except ImportError:
    RemoteYubikeyDevice = YubikeyDevice = None

from .models import (PhoneDevice, get_available_phone_methods,
                     get_available_methods)


class MethodForm(forms.Form):
    """
    A form to choose a two-factor authentication method (e.g. SMS, OTP).
    """ 
    method = forms.ChoiceField(label=_("Method"),
                               initial='generator',
                               widget=forms.RadioSelect)

    def __init__(self, **kwargs):
        super(MethodForm, self).__init__(**kwargs)
        self.fields['method'].choices = get_available_methods()


class PhoneNumberMethodForm(ModelForm):
    """
    A form to provide a phone number, & choose how it's used for
    two-factor authentication.
    """
    method = forms.ChoiceField(widget=forms.RadioSelect, label=_('Method'))

    class Meta:
        model = PhoneDevice
        fields = 'number', 'method',

    def __init__(self, **kwargs):
        super(PhoneNumberMethodForm, self).__init__(**kwargs)
        self.fields['method'].choices = get_available_phone_methods()


class PhoneNumberForm(ModelForm):
    """
    A form to provide a phone number for two-factor authentication.
    """
    class Meta:
        model = PhoneDevice
        fields = 'number',


class DeviceValidationForm(forms.Form):
    """
    A form that validates the token provided by a new authentication device.
    """
    token = forms.IntegerField(label=_("Token"), min_value=1, max_value=int('9' * totp_digits()))

    error_messages = {
        'invalid_token': _('Entered token is not valid.'),
    }

    def __init__(self, device, **args):
        super(DeviceValidationForm, self).__init__(**args)
        self.device = device

    def clean_token(self):
        token = self.cleaned_data['token']
        if not self.device.verify_token(token):
            raise forms.ValidationError(self.error_messages['invalid_token'])
        return token


class YubiKeyDeviceForm(DeviceValidationForm):
    """
    A form that validates the OTP token of a new Yubikey device.
    """
    token = forms.CharField(label=_("YubiKey"))

    error_messages = {
        'invalid_token': _("The YubiKey could not be verified."),
    }

    def clean_token(self):
        self.device.public_id = self.cleaned_data['token'][:-32]
        return super(YubiKeyDeviceForm, self).clean_token()


class TOTPDeviceForm(forms.Form):
    """
    A form that verifies a Time-based One Time Password (TOTP) token,
    of a new device
    """
    token = forms.IntegerField(label=_("Token"), min_value=0, max_value=int('9' * totp_digits()))

    error_messages = {
        'invalid_token': _('Entered token is not valid.'),
    }

    def __init__(self, key, user, metadata=None, **kwargs):
        super(TOTPDeviceForm, self).__init__(**kwargs)
        self.key = key
        self.tolerance = 1
        self.t0 = 0
        self.step = 30
        self.drift = 0
        self.digits = totp_digits()
        self.user = user
        self.metadata = metadata or {}

    @property
    def bin_key(self):
        """
        The secret key as a binary string.
        """
        return unhexlify(self.key.encode())

    def clean_token(self):
        token = self.cleaned_data.get('token')
        validated = False
        t0s = [self.t0]
        key = self.bin_key
        if 'valid_t0' in self.metadata:
            t0s.append(int(time()) - self.metadata['valid_t0'])
        for t0 in t0s:
            for offset in range(-self.tolerance, self.tolerance):
                if totp(key, self.step, t0, self.digits, self.drift + offset) == token:
                    self.drift = offset
                    self.metadata['valid_t0'] = int(time()) - t0
                    validated = True
        if not validated:
            raise forms.ValidationError(self.error_messages['invalid_token'])
        return token

    def save(self):
        return TOTPDevice.objects.create(user=self.user, key=self.key,
                                         tolerance=self.tolerance, t0=self.t0,
                                         step=self.step, drift=self.drift,
                                         digits=self.digits,
                                         name='default')


class DisableForm(forms.Form):
    """
    A form for confirming that two-factor authentication should be disabled.
    """
    understand = forms.BooleanField(label=_("Yes, I am sure"))


class AuthenticationTokenForm(OTPAuthenticationFormMixin, Form):
    """
    A form for authenticating users with their token.
    Usually a second authentication factor, in addition to a password.
    """
    otp_token = forms.IntegerField(label=_("Token"), min_value=1,
                                   max_value=int('9' * totp_digits()))

    def __init__(self, user, initial_device, **kwargs):
        """
        `initial_device` is either the user's default device, or the backup
        device when the user chooses to enter a backup token. The token will
        be verified against all devices, it is not limited to the given
        device.
        """
        super(AuthenticationTokenForm, self).__init__(**kwargs)
        self.user = user

        # YubiKey generates a OTP of 44 characters (not digits). So if the
        # user's primary device is a YubiKey, replace the otp_token
        # IntegerField with a CharField.
        if RemoteYubikeyDevice and YubikeyDevice and \
                isinstance(initial_device, (RemoteYubikeyDevice, YubikeyDevice)):
            self.fields['otp_token'] = forms.CharField(label=_('YubiKey'))

    def clean(self):
        self.clean_otp(self.user)
        return self.cleaned_data


class BackupTokenForm(AuthenticationTokenForm):
    """
    A form for authenticating users with a backup device/token.

    Use of a backup token might imply a security problem, e.g.
     - the user's other token(s) have been lost or stolen
     - the user's other token(s) have been compromised
     - an attacker is attempting to bypass the user's other token(s)

    Alternatively use of a backup token may be routine, e.g.
     - the user's other token(s) are have no signal, or battery
     - the user is authenticating on a web browser/user agent
       that's incompatiable with their other token(s)
    """
    otp_token = forms.CharField(label=_("Token"))
