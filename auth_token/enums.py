from django.utils.translation import ugettext_lazy as _

from enumfields import Choice, ChoiceEnum


class AuthorizationRequestType(ChoiceEnum):

    OTP = Choice(1, _('OTP'))
    MOBILE_DEVICE = Choice(2, _('mobile device'))


class AuthorizationRequestResult(ChoiceEnum):

    GRANTED = Choice(1, _('granted'))
    DENIED = Choice(2, _('denied'))


class AuthorizationRequestState(ChoiceEnum):

    GRANTED = Choice(1, _('granted'))
    DENIED = Choice(2, _('denied'))
    WAITING = Choice(3, _('waiting'))
    EXPIRED = Choice(4, _('expired'))
