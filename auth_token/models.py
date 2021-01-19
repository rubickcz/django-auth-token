from datetime import timedelta

from django.conf import settings as django_settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models, IntegrityError
from django.db.utils import IntegrityError
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from enumfields import NumEnumField

from chamber.models import SmartModel, SmartQuerySet, SmartManager

from generic_m2m_field.models import GenericManyToManyField

from auth_token.utils import compute_expires_at, generate_key, hash_key
from auth_token.config import settings

from .enums import AuthorizationRequestType, AuthorizationRequestState, AuthorizationRequestResult


KEY_SALT = 'django-auth-token'


def compute_authorization_token_expires_at(expiration=None):
    return compute_expires_at(expiration or settings.DEFAULT_TOKEN_AGE)


class AuthorizationTokenManager(SmartManager):

    def create(self, **kwargs):
        for attempt in range(settings.MAX_RANDOM_KEY_ITERATIONS + 1):
            try:
                key = generate_key(length=20)
                hashed_key = hash_key(key)
                authorization_token = super().create(key=hashed_key, **kwargs)
                authorization_token.secret_key = key
                return authorization_token
            except IntegrityError:
                if attempt > settings.MAX_RANDOM_KEY_ITERATIONS:
                    raise IntegrityError('Could not produce unique key for authorization token')


class AuthorizationToken(SmartModel):
    """
    The default authorization token model.
    """

    key = models.CharField(
        verbose_name=_('key'),
        max_length=128,
        primary_key=True,
        null=False,
        blank=False
    )
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=django_settings.AUTH_USER_MODEL,
        related_name='authorization_tokens',
        null=False,
        blank=False,
        on_delete=models.CASCADE
    )
    is_active = models.BooleanField(
        verbose_name=_('is active'),
        default=True
    )
    user_agent = models.CharField(
        verbose_name=_('user agent'),
        max_length=256,
        null=True,
        blank=True
    )
    expires_at = models.DateTimeField(
        verbose_name=_('expires at'),
        null=False,
        blank=False,
        default=compute_authorization_token_expires_at
    )
    ip = models.GenericIPAddressField(
        verbose_name=_('IP'),
        null=False,
        blank=False
    )
    auth_slug = models.SlugField(
        verbose_name=_('slug'),
        null=True,
        blank=True
    )
    backend = models.CharField(
        verbose_name=_('backend'),
        max_length=250,
        null=False,
        blank=False
    )
    allowed_cookie = models.BooleanField(
        verbose_name=_('is allowed cookie'),
        default=True
    )
    allowed_header = models.BooleanField(
        verbose_name=_('is allowed header'),
        default=True
    )
    is_authenticated = models.BooleanField(
        verbose_name=_('is authenticated'),
        null=False,
        blank=False,
        default=False
    )
    preserve_cookie = models.BooleanField(
        verbose_name=_('preserve cookie'),
        null=False,
        blank=False,
        default=False
    )

    related_objects = GenericManyToManyField()

    is_from_header = False
    is_from_cookie = False
    secret_key = None

    objects = AuthorizationTokenManager()

    class Meta:
        verbose_name = _('authorization token')
        verbose_name_plural = _('authorization tokens')

    @property
    def active_takeover(self):
        return self.user_takeovers.filter(is_active=True).last()

    @property
    def is_expired(self):
        return self.expires_at < timezone.now()

    @property
    def time_to_expiration(self):
        return self.expires_at - timezone.now()

    @property
    def str_time_to_expiration(self):
        return str(self.time_to_expiration) if self.time_to_expiration.total_seconds() > 0 else '00:00:00'


class AnonymousAuthorizationToken:

    key = None
    user = AnonymousUser
    creted_at = None
    is_active = False
    user_agent = None
    expiration = None
    is_from_header = False
    is_from_cookie = False
    active_takeover = None
    backend = None
    allowed_cookie = False
    allowed_header = False
    secret_key = None
    is_authenticated = False

    def save(self):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError


class UserAuthorizationTokenTakeover(SmartModel):
    """
    The model allows to change user without token change
    """

    token = models.ForeignKey(
        verbose_name=_('authorization token'),
        to=AuthorizationToken,
        related_name='user_takeovers',
        on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=django_settings.AUTH_USER_MODEL,
        related_name='user_token_takeovers',
        null=False,
        blank=False,
        on_delete=models.CASCADE
    )
    is_active = models.BooleanField()

    class Meta:
        verbose_name = _('authorization takeover')
        verbose_name_plural = _('authorization takeovers')


class MobileDeviceAlreadyExists(Exception):
    pass


class MobileDeviceQuerySet(SmartQuerySet):

    def create_token(self, uuid, user, user_agent=''):
        """
        This method must be called when user is authenticated.
        It creates a new MobileDevice with auto generated token for the device and returns token.
        If MobileDevice with same UUID exists MobileDeviceAlreadyExists is raised.
        """
        token = generate_key(length=64)
        is_created_mobile_device = self.get_or_create(
            uuid=uuid, user=user,
            defaults={
                'login_token': make_password(token),
                'user_agent': user_agent[:256],
                'is_active': True
            }
        )[1]
        if is_created_mobile_device:
            return token
        else:
            raise MobileDeviceAlreadyExists('Device key already exists')


class MobileDevice(SmartModel):
    """Model used to authenticate mobile devices. Unhashed login_token is stored
    in the device keychain and serve as password to log in together with UUID via DeviceBackend."""

    # this is not UUIDField because of the strict length limitation
    uuid = models.CharField(
        verbose_name=_('UUID'),
        max_length=32,
        null=False,
        blank=False
    )
    last_login = models.DateTimeField(
        verbose_name=_('last login'),
        null=True,
        blank=True
    )
    user = models.ForeignKey(
        to=django_settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        verbose_name=_('user')
    )
    login_token = models.CharField(
        max_length=128,
        verbose_name=_('login token'),
        null=False,
        blank=False
    )
    is_active = models.BooleanField(
        verbose_name=_('is active'),
        default=True
    )
    user_agent = models.CharField(
        verbose_name=_('user agent'),
        max_length=256,
        null=True,
        blank=True,
    )

    class Meta:
        unique_together = ('uuid', 'user')
        verbose_name = _('mobile device')
        verbose_name_plural = _('mobile devices')

    objects = MobileDeviceQuerySet.as_manager()

    def check_password(self, token):
        return check_password(token, self.login_token)


class VerificationTokenManager(models.Manager):

    def deactivate(self, obj, slug=None, key=None):
        self.filter_active_tokens(obj, slug, key).update(is_active=False)

    def deactivate_and_create(self, obj, slug=None, extra_data=None, deactivate_old_tokens=True,
                              key_generator_kwargs=None, **kwargs):
        if deactivate_old_tokens:
            self.deactivate(obj, slug)

        return self._create(obj, slug=slug, extra_data=extra_data, key_generator_kwargs=key_generator_kwargs, **kwargs)

    def get_active_or_create(self, obj, slug=None, extra_data=None, key=None, key_generator_kwargs=None, **kwargs):
        token = self.filter_active_tokens(obj, slug, key).order_by('created_at').last()

        if token and token.is_valid:
            return token
        else:
            return self._create(obj, slug=slug, extra_data=extra_data, key_generator_kwargs=key_generator_kwargs,
                                **kwargs
            )

    def _create(self, obj, slug=None, extra_data=None, key_generator_kwargs=None, **kwargs):
        expiration_in_minutes = kwargs.pop('expiration_in_minutes', settings.DEFAULT_EXPIRATION)
        key_generator_kwargs = {} if key_generator_kwargs is None else key_generator_kwargs

        token = self.model(
            content_type=ContentType.objects.get_for_model(obj.__class__),
            object_id=obj.pk,
            slug=slug,
            expires_at=(timezone.now() + timedelta(minutes=expiration_in_minutes)) if expiration_in_minutes else None,
            key=self.model.generate_key(**key_generator_kwargs),
        )
        if extra_data:
            token.set_extra_data(extra_data)

        token.save()
        return token

    def exists_valid(self, obj, key, slug=None):
        for token in self.filter_active_tokens(obj, slug):
            if token.check_key(key):
                return True
        return False

    def filter_active_tokens(self, obj_or_class, slug=None, key=None):
        qs = self.filter(
            is_active=True,
            slug=slug,
        )

        if isinstance(obj_or_class, models.Model):
            qs = qs.filter(object_id=obj_or_class.pk)
        return qs.filter(key=key) if key else qs


class OneTimePasswordManager(SmartManager):

    def create(self, key_generator, **kwargs):
        for attempt in range(settings.MAX_RANDOM_KEY_ITERATIONS + 1):
            try:
                key = key_generator()
                hashed_key = hash_key(key)
                obj = super().create(key=hashed_key, **kwargs)
                obj.secret_key = key
                return obj
            except IntegrityError:
                if attempt > settings.MAX_RANDOM_KEY_ITERATIONS:
                    raise IntegrityError('Could not produce unique key for authorization token')


class OneTimePassword(SmartModel):
    """
    Specific verification tokens that can be send via e-mail, SMS or another transmission medium
    to check user authorization (example password reset)
    """
    key = models.CharField(
        verbose_name=_('key'),
        max_length=128,
        primary_key=True,
        null=False,
        blank=False
    )
    expires_at = models.DateTimeField(
        verbose_name=_('expires at'),
        null=True,
        blank=True,
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        null=False,
        blank=False
    )
    is_active = models.BooleanField(
        verbose_name=_('is active'),
        default=True
    )
    data = models.JSONField(
        verbose_name=_('data'),
        null=True,
        blank=True,
        encoder=DjangoJSONEncoder
    )
    related_objects = GenericManyToManyField()

    secret_key = None

    objects = OneTimePasswordManager()

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _('one time password')
        verbose_name_plural = _('one time passwords')

    def check_key(self, key):
        return self.key == hash_key(key)

    @property
    def is_expired(self):
        return self.expires_at and self.expires_at < timezone.now()


class AuthorizationRequest(SmartModel):

    authorization_token = models.OneToOneField(
        verbose_name=_('authorization token'),
        to=AuthorizationToken,
        related_name='authorization_request',
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=django_settings.AUTH_USER_MODEL,
        related_name='authorization_requests',
        null=False,
        blank=False,
        on_delete=models.CASCADE
    )
    mobile_device = models.ForeignKey(
        verbose_name=_('mobile device'),
        to=MobileDevice,
        related_name='authorization_requests',
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )
    one_time_password = models.OneToOneField(
        verbose_name=_('one time password'),
        to=OneTimePassword,
        related_name='authorization_request',
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        null=True,
        blank=True
    )
    title = models.CharField(
        verbose_name=_('title'),
        max_length=250,
        null=False,
        blank=False
    )
    description = models.TextField(
        verbose_name=_('description'),
        null=True,
        blank=True
    )
    result = NumEnumField(
        verbose_name=_('result'),
        enum=AuthorizationRequestResult,
        null=True,
        blank=True
    )
    type = NumEnumField(
        verbose_name=_('type'),
        enum=AuthorizationRequestType,
        null=False,
        blank=False
    )
    data = models.JSONField(
        verbose_name=_('data'),
        null=True,
        blank=True,
        encoder=DjangoJSONEncoder
    )
    expires_at = models.DateTimeField(
        verbose_name=_('expires at'),
        null=True,
        blank=True,
    )
    related_objects = GenericManyToManyField()

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _('authorization request')
        verbose_name_plural = _('authorization requests')

    @property
    def is_expired(self):
        return self.expires_at < timezone.now()

    @property
    def state(self):
        if not self.result and self.is_expired:
            return AuthorizationRequestState.EXPIRED
        elif not self.result:
            return AuthorizationRequestState.WAITING
        else:
            return AuthorizationRequestState(self.result.value)
