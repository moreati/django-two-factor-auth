from django.forms import fields
from django.forms import widgets

from .utils import totp_digits
from .widgets import OTPTokenInput, TokenInput


class TokenField(fields.CharField):
    widget = TokenInput


class OTPTokenField(TokenField):
    widget = OTPTokenInput

    def __init__(self, digits=None, *args, **kwargs):
        if digits is None:
            digits = totp_digits()
        self.digits = digits
        super(OTPTokenField, self).__init__(min_length=digits,
                                            max_length=digits,
                                            *args, **kwargs)
