from datetime import timedelta

from freezegun import freeze_time

from django.core.management import call_command
from django.utils import timezone

from germanium.decorators import data_consumer
from germanium.test_cases.default import GermaniumTestCase
from germanium.tools import assert_equal, test_call_command

from auth_token.enums import AuthorizationRequestType
from auth_token.models import AuthorizationToken, OneTimePassword, AuthorizationRequest
from auth_token.config import settings
from auth_token.utils import generate_key

from .base import BaseTestCaseMixin


__all__ = (
   'CleanTokensCommandTestCase',
)


class CleanTokensCommandTestCase(BaseTestCaseMixin, GermaniumTestCase):

    @data_consumer('create_user')
    def test_clean_authorization_tokens_should_remove_only_old_tokens(self, user):
        expired_tokens = [
            AuthorizationToken.objects.create(user=user, ip='127.0.0.1', backend='test') for _ in range(10)
        ]
        not_expired_tokens = [
            AuthorizationToken.objects.create(user=user, ip='127.0.0.1', backend='test', expires_at=timezone.now())
            for _ in range(settings.COUNT_USER_PRESERVED_TOKENS - 5)
        ]
        test_call_command('clean_authorization_tokens')
        assert_equal(AuthorizationToken.objects.filter(pk__in=[token.pk for token in not_expired_tokens]).count(),
                     settings.COUNT_USER_PRESERVED_TOKENS - 5)
        assert_equal(AuthorizationToken.objects.filter(pk__in=[token.pk for token in expired_tokens]).count(), 5)

    @data_consumer('create_user')
    def test_clean_one_time_password_should_remove_only_inactive_or_expired_otp(self, user):
        expired_otp = [
            OneTimePassword.objects.create(key_generator=generate_key, expires_at=timezone.now(), slug='test')
            for _ in range(10)
        ]
        inactive_otp = [
            OneTimePassword.objects.create(key_generator=generate_key, is_active=False, slug='test')
            for _ in range(10)
        ]
        not_expired_otp = [
            OneTimePassword.objects.create(key_generator=generate_key, slug='test')
            for _ in range(10)
        ]
        expired_with_authorization_request = OneTimePassword.objects.create(
            key_generator=generate_key, expires_at=timezone.now(), slug='test'
        )
        AuthorizationRequest.objects.create(
            type=AuthorizationRequestType.OTP,
            one_time_password=expired_with_authorization_request,
            user=user,
            slug='test',
            title='test'
        )

        test_call_command('clean_one_time_passwords')
        assert_equal(OneTimePassword.objects.filter(pk__in=[obj.pk for obj in expired_otp]).count(), 0)
        assert_equal(OneTimePassword.objects.filter(pk__in=[obj.pk for obj in inactive_otp]).count(), 0)
        assert_equal(OneTimePassword.objects.filter(pk__in=[obj.pk for obj in not_expired_otp]).count(), 10)
        assert_equal(OneTimePassword.objects.filter(pk=expired_with_authorization_request.pk).count(), 1)

    @data_consumer('create_user')
    def test_clean_authorization_requests_should_remove_only_old_objects(self, user):
        authorization_requests = [
            AuthorizationRequest.objects.create(
                type=AuthorizationRequestType.OTP,
                slug='test',
                user=user,
                title='test',
                expires_at=timezone.now()
            ) for _ in range(10)
        ]

        test_call_command('clean_authorization_requests')
        assert_equal(AuthorizationRequest.objects.filter(pk__in=[obj.pk for obj in authorization_requests]).count(), 10)

        with freeze_time(timezone.now() + timedelta(days=7, seconds=1)):
            test_call_command('clean_authorization_requests')
            assert_equal(
                AuthorizationRequest.objects.filter(pk__in=[obj.pk for obj in authorization_requests]).count(),
                0
            )
