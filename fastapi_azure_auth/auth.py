import inspect
import logging
from typing import Any, Awaitable, Callable, Dict, Literal, Optional
from warnings import warn

from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi.security.base import SecurityBase
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.requests import Request

from fastapi_azure_auth.exceptions import InvalidAuth
from fastapi_azure_auth.openid_config import OpenIdConfig
from fastapi_azure_auth.user import User
from fastapi_azure_auth.utils import is_guest

log = logging.getLogger('fastapi_azure_auth')


class AzureAuthorizationCodeBearerBase(SecurityBase):
    def __init__(
        self,
        app_client_id: str,
        auto_error: bool = True,
        tenant_id: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        multi_tenant: bool = False,
        validate_iss: bool = True,
        iss_callable: Optional[Callable[[str], Awaitable[str]]] = None,
        token_version: Literal[1, 2] = 2,
        allow_guest_users: bool = False,
        openid_config_use_app_id: bool = False,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openid_config_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings.

        :param app_client_id: str
            Your application client ID. This will be the `Web app` in Azure AD
        :param auto_error: bool
            Whether to throw exceptions or return None on __call__.
        :param tenant_id: str
            Your Azure tenant ID, only needed for single tenant apps
        :param scopes: Optional[dict[str, str]
            Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }

        :param multi_tenant: bool
            Whether this is a multi tenant or single tenant application.
        :param validate_iss: bool
        **Only used for multi-tenant applications**
            Whether to validate the token `iss` (issuer) or not. This can be skipped to allow anyone to log in.
        :param iss_callable: Async Callable
        **Only used for multi-tenant application**
            Async function that has to accept a `tid` (tenant ID) and return a `iss` (issuer) or
             raise an InvalidIssuer exception
            This is required when validate_iss is set to `True`.

        :param allow_guest_users: bool
            Whether to allow guest users or not. Guest users can be added manually, or by other services, such as
            inviting them to a teams channel. Most developers do _not_ want guest users in their applications.

        :param token_version: int
            Version of the token expected from the token endpoint. Defaults to `2`, but can be set to `1` for single
            tenant applications.
        :param openid_config_use_app_id: bool
            Set this to True if you're using claims-mapping. If you're unsure, leave at False.
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#sample-response

        :param openapi_authorization_url: str
            Override OpenAPI authorization URL
        :param openapi_token_url: str
            Override OpenAPI token URL
        :param openid_config_url: str
            Override OpenID config URL (used for B2C tenants)
        :param openapi_description: str
            Override OpenAPI description
        """
        self.auto_error = auto_error
        # Validate settings, making sure there's no misconfigured dependencies out there
        if multi_tenant:
            if validate_iss and not callable(iss_callable):
                raise RuntimeError('`validate_iss` is enabled, so you must provide an `iss_callable`')
            elif iss_callable and 'tid' not in inspect.signature(iss_callable).parameters.keys():
                raise RuntimeError('`iss_callable` must accept `tid` as an argument')

        self.app_client_id: str = app_client_id
        self.multi_tenant: bool = multi_tenant
        self.openid_config: OpenIdConfig = OpenIdConfig(
            tenant_id=tenant_id,
            multi_tenant=self.multi_tenant,
            token_version=token_version,
            app_id=app_client_id if openid_config_use_app_id else None,
            config_url=openid_config_url or None,
        )

        self.validate_iss: bool = validate_iss
        self.iss_callable: Optional[Callable[..., Any]] = iss_callable
        self.token_version: int = token_version
        if self.token_version == 1:
            warn(
                'v1 token support will be removed in a future release. Please migrate to v2 tokens.', DeprecationWarning
            )
        self.allow_guest_users = allow_guest_users
        # Define settings for `OAuth2AuthorizationCodeBearer` and OpenAPI Authorization
        self.authorization_url = openapi_authorization_url
        self.token_url = openapi_token_url
        if not self.authorization_url:
            if multi_tenant:
                self.authorization_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
            else:
                self.authorization_url = (
                    f'https://login.microsoftonline.com/{self.openid_config.tenant_id}/oauth2/v2.0/authorize'
                )
        if not self.token_url:
            if multi_tenant:
                self.token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
            else:
                self.token_url = f'https://login.microsoftonline.com/{self.openid_config.tenant_id}/oauth2/v2.0/token'

        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=self.authorization_url,
            tokenUrl=self.token_url,
            scopes=scopes,
            scheme_name='AzureAuthorizationCodeBearerBase',
            description=openapi_description or '`Leave client_secret blank`',
            auto_error=True,  # We catch this exception in __call__
        )
        self.model = self.oauth.model

    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> Optional[User]:
        """
        Extends call to also validate the token.
        """
        try:
            access_token = await self.oauth(request=request)
            try:
                # Extract header information of the token.
                header: dict[str, str] = jwt.get_unverified_header(token=access_token) or {}
                claims: dict[str, Any] = jwt.get_unverified_claims(token=access_token) or {}
            except Exception as error:
                log.warning('Malformed token received. %s. Error: %s', access_token, error, exc_info=True)
                raise InvalidAuth(detail='Invalid token format') from error

            user_is_guest: bool = is_guest(claims=claims)
            if not self.allow_guest_users and user_is_guest:
                log.info('User denied, is a guest user', claims)
                raise InvalidAuth(detail='Guest users not allowed')

            for scope in security_scopes.scopes:
                token_scope_string = claims.get('scp', '')
                log.debug('Scopes: %s', token_scope_string)
                if not isinstance(token_scope_string, str):
                    raise InvalidAuth('Token contains invalid formatted scopes')

                token_scopes = token_scope_string.split(' ')
                if scope not in token_scopes:
                    raise InvalidAuth('Required scope missing')
            # Load new config if old
            await self.openid_config.load_config()

            if self.multi_tenant and self.validate_iss and self.iss_callable:
                iss = await self.iss_callable(tid=claims.get('tid'))
            else:
                iss = self.openid_config.issuer

            # Use the `kid` from the header to find a matching signing key to use
            try:
                if key := self.openid_config.signing_keys.get(header.get('kid', '')):
                    # We require and validate all fields in an Azure AD token
                    options = {
                        'verify_signature': True,
                        'verify_aud': True,
                        'verify_iat': True,
                        'verify_exp': True,
                        'verify_nbf': True,
                        'verify_iss': self.validate_iss,
                        'verify_sub': True,
                        'verify_jti': True,
                        'verify_at_hash': True,
                        'require_aud': True,
                        'require_iat': True,
                        'require_exp': True,
                        'require_nbf': True,
                        'require_iss': self.validate_iss,
                        'require_sub': True,
                        'require_jti': False,
                        'require_at_hash': False,
                        'leeway': 0,
                    }
                    # Validate token
                    token = jwt.decode(
                        access_token,
                        key=key,
                        algorithms=['RS256'],
                        audience=self.app_client_id if self.token_version == 2 else f'api://{self.app_client_id}',
                        issuer=iss,
                        options=options,
                    )
                    # Attach the user to the request. Can be accessed through `request.state.user`
                    user: User = User(
                        **{**token, 'claims': token, 'access_token': access_token, 'is_guest': user_is_guest}
                    )
                    request.state.user = user
                    return user
            except JWTClaimsError as error:
                log.info('Token contains invalid claims. %s', error)
                raise InvalidAuth(detail='Token contains invalid claims') from error
            except ExpiredSignatureError as error:
                log.info('Token signature has expired. %s', error)
                raise InvalidAuth(detail='Token signature has expired') from error
            except JWTError as error:
                log.warning('Invalid token. Error: %s', error, exc_info=True)
                raise InvalidAuth(detail='Unable to validate token') from error
            except Exception as error:
                # Extra failsafe in case of a bug in a future version of the jwt library
                log.exception('Unable to process jwt token. Uncaught error: %s', error)
                raise InvalidAuth(detail='Unable to process token') from error
            log.warning('Unable to verify token. No signing keys found')
            raise InvalidAuth(detail='Unable to verify token, no signing keys found')
        except (HTTPException, InvalidAuth):
            if not self.auto_error:
                return None
            raise


class SingleTenantAzureAuthorizationCodeBearer(AzureAuthorizationCodeBearerBase):
    def __init__(
        self,
        app_client_id: str,
        tenant_id: str,
        auto_error: bool = True,
        scopes: Optional[Dict[str, str]] = None,
        allow_guest_users: bool = False,
        token_version: Literal[1, 2] = 2,
        openid_config_use_app_id: bool = False,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings for a single tenant application.

        :param app_client_id: str
            Your application client ID. This will be the `Web app` in Azure AD
        :param tenant_id: str
            Your Azure tenant ID, only needed for single tenant apps
        :param auto_error: bool
            Whether to throw exceptions or return None on __call__.
        :param scopes: Optional[dict[str, str]
            Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }
        :param allow_guest_users: bool
            Whether to allow guest users or not. Guest users can be added manually, or by other services, such as
            inviting them to a teams channel. Most developers do _not_ want guest users in their applications.
        :param token_version: int
            Version of the token expected from the token endpoint. Defaults to `2`, but can be set to `1` for single
            tenant applications.
        :param openid_config_use_app_id: bool
            Set this to True if you're using claims-mapping. If you're unsure, leave at False.
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#sample-response

        :param openapi_authorization_url: str
            Override OpenAPI authorization URL
        :param openapi_token_url: str
            Override OpenAPI token URL
        :param openapi_description: str
            Override OpenAPI description
        """
        super().__init__(
            app_client_id=app_client_id,
            auto_error=auto_error,
            tenant_id=tenant_id,
            scopes=scopes,
            allow_guest_users=allow_guest_users,
            token_version=token_version,
            openid_config_use_app_id=openid_config_use_app_id,
            openapi_authorization_url=openapi_authorization_url,
            openapi_token_url=openapi_token_url,
            openapi_description=openapi_description,
        )
        self.scheme_name: str = 'Azure AD - PKCE, Single-tenant'


class MultiTenantAzureAuthorizationCodeBearer(AzureAuthorizationCodeBearerBase):
    def __init__(
        self,
        app_client_id: str,
        auto_error: bool = True,
        scopes: Optional[Dict[str, str]] = None,
        validate_iss: bool = True,
        iss_callable: Optional[Callable[[str], Awaitable[str]]] = None,
        allow_guest_users: bool = False,
        openid_config_use_app_id: bool = False,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings for a multi-tenant application.

        :param app_client_id: str
            Your application client ID. This will be the `Web app` in Azure AD
        :param auto_error: bool
            Whether to throw exceptions or return None on __call__.
        :param scopes: Optional[dict[str, str]
            Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }

        :param validate_iss: bool
            Whether to validate the token `iss` (issuer) or not. This can be skipped to allow anyone to log in.
        :param iss_callable: Async Callable
            Async function that has to accept a `tid` (tenant ID) and return a `iss` (issuer) or
             raise an InvalidIssuer exception
            This is required when validate_iss is set to `True`.

        :param allow_guest_users: bool
            Whether to allow guest users or not. Guest users can be added manually, or by other services, such as
            inviting them to a teams channel. Most developers do _not_ want guest users in their applications.

        :param openid_config_use_app_id: bool
            Set this to True if you're using claims-mapping. If you're unsure, leave at False.
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#sample-response

        :param openapi_authorization_url: str
            Override OpenAPI authorization URL
        :param openapi_token_url: str
            Override OpenAPI token URL
        :param openapi_description: str
            Override OpenAPI description
        """
        super().__init__(
            app_client_id=app_client_id,
            auto_error=auto_error,
            scopes=scopes,
            validate_iss=validate_iss,
            iss_callable=iss_callable,
            allow_guest_users=allow_guest_users,
            multi_tenant=True,
            openid_config_use_app_id=openid_config_use_app_id,
            openapi_authorization_url=openapi_authorization_url,
            openapi_token_url=openapi_token_url,
            openapi_description=openapi_description,
        )
        self.scheme_name: str = 'Azure AD - PKCE, Multi-tenant'


class B2CMultiTenantAuthorizationCodeBearer(AzureAuthorizationCodeBearerBase):
    def __init__(
        self,
        app_client_id: str,
        auto_error: bool = True,
        scopes: Optional[Dict[str, str]] = None,
        validate_iss: bool = True,
        iss_callable: Optional[Callable[[str], Awaitable[str]]] = None,
        openid_config_use_app_id: bool = False,
        openid_config_url: Optional[str] = None,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings for a B2C multi-tenant application.
        :param app_client_id: str
            Your application client ID. This will be the `Web app` in Azure AD
        :param openid_config_url: str
            Override OpenID config URL (used for B2C tenants)
        :param auto_error: bool
            Whether to throw exceptions or return None on __call__.
        :param scopes: Optional[dict[str, str]
            Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }
        :param validate_iss: bool
            Whether to validate the token `iss` (issuer) or not. This can be skipped to allow anyone to log in.
        :param iss_callable: Async Callable
            Async function that has to accept a `tid` (tenant ID) and return a `iss` (issuer) or
             raise an InvalidIssuer exception
            This is required when validate_iss is set to `True`.
        :param openid_config_use_app_id: bool
            Set this to True if you're using claims-mapping. If you're unsure, leave at False.
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#sample-response
        :param openapi_authorization_url: str
            Override OpenAPI authorization URL
        :param openapi_token_url: str
            Override OpenAPI token URL
        :param openapi_description: str
            Override OpenAPI description
        """
        super().__init__(
            app_client_id=app_client_id,
            auto_error=auto_error,
            scopes=scopes,
            validate_iss=validate_iss,
            iss_callable=iss_callable,
            multi_tenant=True,
            allow_guest_users=True,
            openid_config_use_app_id=openid_config_use_app_id,
            openid_config_url=openid_config_url,
            openapi_authorization_url=openapi_authorization_url,
            openapi_token_url=openapi_token_url,
            openapi_description=openapi_description,
        )
        self.scheme_name: str = 'Azure AD - PKCE, B2C Multi-tenant'
