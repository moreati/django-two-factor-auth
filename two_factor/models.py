from binascii import unhexlify
import json
import logging

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import ugettext_lazy as _

from django_otp import Device
from django_otp.oath import totp
from django_otp.util import hex_validator, random_hex

from u2flib_server import u2f_v2 as u2f

try:
    import yubiotp
except ImportError:
    yubiotp = None

from .gateways import make_call, send_sms


logger = logging.getLogger(__name__)

phone_number_validator = RegexValidator(
    code='invalid-phone-number',
    regex='^(\+|00)',
    message=_('Please enter a valid phone number, including your country code '
              'starting with + or 00.'),
)

PHONE_METHODS = (
    ('call', _('Phone Call')),
    ('sms', _('Text Message')),
)


def get_available_phone_methods():
    methods = []
    if getattr(settings, 'TWO_FACTOR_CALL_GATEWAY', None):
        methods.append(('call', _('Phone call')))
    if getattr(settings, 'TWO_FACTOR_SMS_GATEWAY', None):
        methods.append(('sms', _('Text message')))
    return methods


def get_available_yubikey_methods():
    methods = []
    if yubiotp and 'otp_yubikey' in settings.INSTALLED_APPS:
        methods.append(('yubikey', _('YubiKey')))
    return methods


def get_available_u2f_methods():
    return [('u2f', _('U2F'))]


def get_available_methods():
    methods = [('generator', _('Token generator'))]
    methods.extend(get_available_phone_methods())
    methods.extend(get_available_yubikey_methods())
    methods.extend(get_available_u2f_methods())
    return methods


def key_validator(*args, **kwargs):
    """Wraps hex_validator generator, to keep makemigrations happy."""
    return hex_validator()(*args, **kwargs)


class PhoneDevice(Device):
    """
    Model with phone number and token seed linked to a user.
    """
    number = models.CharField(max_length=16,
                              validators=[phone_number_validator],
                              verbose_name=_('number'))
    key = models.CharField(max_length=40,
                           validators=[key_validator],
                           default=random_hex,
                           help_text="Hex-encoded secret key")
    method = models.CharField(max_length=4, choices=PHONE_METHODS,
                              verbose_name=_('method'))

    def __repr__(self):
        return '<PhoneDevice(number={!r}, method={!r}>'.format(
            self.number,
            self.method,
        )

    def __eq__(self, other):
        if not isinstance(other, PhoneDevice):
            return False
        return self.number == other.number \
            and self.method == other.method \
            and self.key == other.key

    @property
    def bin_key(self):
        return unhexlify(self.key.encode())

    def verify_token(self, token):
        # local import to avoid circular import
        from two_factor.utils import totp_digits

        try:
            token = int(token)
        except ValueError:
            return False

        for drift in range(-5, 1):
            if totp(self.bin_key, drift=drift, digits=totp_digits()) == token:
                return True
        return False

    def generate_challenge(self):
        # local import to avoid circular import
        from two_factor.utils import totp_digits

        """
        Sends the current TOTP token to `self.number` using `self.method`.
        """
        no_digits = totp_digits()
        token = str(totp(self.bin_key, digits=no_digits)).zfill(no_digits)
        if self.method == 'call':
            make_call(device=self, token=token)
        else:
            send_sms(device=self, token=token)


class U2FDevice(Device):
    """
    Represents a U2F device
    :class:`~django_otp.models.Device`.
    """
    public_key = models.TextField()
    key_handle = models.TextField()
    app_id = models.TextField()

    counter = models.PositiveIntegerField(
        default=0,
        help_text="The non-volatile login counter most recently used by this device."
    )

    challenge = models.TextField()

    class Meta(Device.Meta):
        verbose_name = "U2F device"

    def to_json(self):
        return {
            'publicKey': self.public_key,
            'keyHandle': self.key_handle,
            'appId': self.app_id,
        }

    def generate_registration(self):
        if self.key_handle:
            raise RuntimeError("Why are you trying to register this device again?")
        challenge = u2f.start_register(self.app_id)
        self.challenge = challenge
        #self.save()
        return "Activate your U2F device to complete registration"

    def verify_registration(self, token):
        challenge = self.challenge
        device, attestation_cert = u2f.complete_register(challenge, token)

        self.key_handle = device['keyHandle']
        self.public_key = device['publicKey']
        self.app_id = device['appId']
        self.challenge = ''
        return True

    def generate_challenge(self):
        sign_request = u2f.start_authenticate(self.to_json())
        self.challenge = json.dumps(sign_request)
        self.save()
        return "Activate your U2F device to authenticate"

    def verify_token(self, token):
        registration = self.to_json()
        challenge = self.challenge
        response = token
        try:
            counter, touch_asserted = u2f.verify_authenticate(
                registration, challenge, response)
        except SystemExit:
            print repr(token)
            logger.exception('foo')
            return False

        if counter <= self.counter:
            # Could indicate an attack, e.g. the device has been cloned
            return False

        self.counter = counter
        self.challenge = ''
        self.save()

        return True
