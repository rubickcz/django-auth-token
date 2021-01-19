from datetime import timedelta

from django.utils import timezone

from germanium.decorators import data_consumer
from germanium.test_cases.default import GermaniumTestCase
from germanium.tools import assert_equal, assert_true, assert_false

from auth_token.models import AuthorizationToken
from auth_token.config import settings

from .base import BaseTestCaseMixin


__all__ = (
    'TokenTestCase',
)


class TokenTestCase(BaseTestCaseMixin, GermaniumTestCase):

    @data_consumer('create_user')
    def test_should_return_proper_string_format_for_expiration(self, user):
        expired_token = AuthorizationToken.objects.create(
            user=user, ip='127.0.0.1', backend='test', expires_at=timezone.now()
        )
        expired_token = AuthorizationToken.objects.get(pk=expired_token.pk)
        assert_equal('00:00:00', AuthorizationToken.objects.get(pk=expired_token.pk).str_time_to_expiration)

        non_expired_token = AuthorizationToken.objects.create(user=user, ip='127.0.0.1', backend='test')
        assert_equal('0:59:59', non_expired_token.str_time_to_expiration.split('.')[0])
