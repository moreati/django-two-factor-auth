from django.forms import widgets
from django.utils.translation import ugettext as _


class TelInput(widgets.Input):
    input_type = 'tel'


class TokenInput(widgets.TextInput):
    def __init__(self, attrs=None):
        # One time passwords are by their nature single use
        default_attrs = {'autocomplete': 'off'}
        if attrs:
            default_attrs.update(attrs)
        super(TokenInput, self).__init__(default_attrs)


# type=number, pattern=[0-9]* would also trigger the keypad on iPhones, but
# - It may cause browsers to strip leading zeros
# - It may cause browsers to put thousand seperators in the submitted value
# - Desktop browsers display it with a spinner control.
# - It's semantically worse - an OTP token has digits, but it's not a number

class OTPTokenInput(TokenInput):
    # Hack: <input type=tel ...> is not strictly correct for a OTP token,
    #       but it triggers many mobile devices to use a numeric keypad
    #       e.g. Safari on iPhones, Chrome on many Android phones.
    #       Remove this once browsers support inputmode.
    input_type = 'tel'

    def __init__(self, attrs=None):
        # Part of the HTML5 standard, not yet implemented by most browsers
        default_attrs = {
            'inputmode': 'numeric',
        }
        if attrs:
            default_attrs.update(attrs)
        super(OTPTokenInput, self).__init__(default_attrs)
