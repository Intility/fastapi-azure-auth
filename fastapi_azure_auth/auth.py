import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import Any, Literal, Optional

from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi.security.base import SecurityBase
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.requests import Request

from fastapi_azure_auth.exceptions import InvalidAuth
from fastapi_azure_auth.openid_config import OpenIdConfig
from fastapi_azure_auth.user import User

log = logging.getLogger('fastapi_azure_auth')


class AzureAuthorizationCodeBearerBase(SecurityBase):
    def __init__(
        self,
        app_client_id: str,
        tenant_id: Optional[str] = None,
        scopes: Optional[dict[str, str]] = None,
        multi_tenant: bool = False,
        validate_iss: bool = True,
        iss_callable: Optional[Callable[..., Any]] = None,
        token_version: Literal[1, 2] = 2,
        openid_config_use_app_id: bool = False,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings.

        :param app_client_id: str
            Your applications client ID. This will be the `Web app` in Azure AD
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
        :param iss_callable: Callable
        **Only used for multi-tenant application**
            Async function that has to accept a `tid` (tenant ID) and return a `iss` (issuer) or
             raise an InvalidIssuer exception
            This is required when validate_iss is set to `True`.

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
        # Validate settings, making sure there's no misconfigured dependencies out there
        if multi_tenant:
            if validate_iss and not callable(iss_callable):
                raise RuntimeError('`validate_iss` is enabled, so you must provide an `iss_callable`')
            elif iss_callable and not asyncio.iscoroutinefunction(iss_callable):
                raise RuntimeError('`iss_callable` must be a coroutine')
            elif iss_callable and 'tid' not in inspect.signature(iss_callable).parameters.keys():
                raise RuntimeError('`iss_callable` must accept `tid` as an argument')

        self.app_client_id: str = app_client_id
        self.multi_tenant: bool = multi_tenant
        self.openid_config: OpenIdConfig = OpenIdConfig(
            tenant_id=tenant_id,
            multi_tenant=self.multi_tenant,
            token_version=token_version,
            app_id=app_client_id if openid_config_use_app_id else None,
        )
        self.validate_iss: bool = validate_iss
        self.iss_callable: Optional[Callable[..., Any]] = iss_callable
        self.token_version: int = token_version

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
            auto_error=True,
        )
        self.model = self.oauth.model

    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> User:
        """
        Extends call to also validate the token.
        """
        access_token = await self.oauth(request=request)
        try:
            # Extract header information of the token.
            header: dict[str, str] = jwt.get_unverified_header(token=access_token) or {}
            claims: dict[str, Any] = jwt.get_unverified_claims(token=access_token) or {}
        except Exception as error:
            log.warning('Malformed token received. %s. Error: %s', access_token, error, exc_info=True)
            raise InvalidAuth(detail='Invalid token format')

        for scope in security_scopes.scopes:
            token_scope_string = claims.get('scp', '')
            if isinstance(token_scope_string, str):
                token_scopes = token_scope_string.split(' ')
                if scope not in token_scopes:
                    raise InvalidAuth('Required scope missing')
            else:
                raise InvalidAuth('Token contains invalid formatted scopes')

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
                user: User = User(**token | {'claims': token, 'access_token': access_token})
                request.state.user = user
                return user
        except JWTClaimsError as error:
            log.info('Token contains invalid claims. %s', error)
            raise InvalidAuth(detail='Token contains invalid claims')
        except ExpiredSignatureError as error:
            log.info('Token signature has expired. %s', error)
            raise InvalidAuth(detail='Token signature has expired')
        except JWTError as error:
            log.warning('Invalid token. Error: %s', error, exc_info=True)
            raise InvalidAuth(detail='Unable to validate token')
        except Exception as error:
            # Extra failsafe in case of a bug in a future version of the jwt library
            log.exception('Unable to process jwt token. Uncaught error: %s', error)
            raise InvalidAuth(detail='Unable to process token')
        log.warning('Unable to verify token. No signing keys found')
        raise InvalidAuth(detail='Unable to verify token, no signing keys found')


class SingleTenantAzureAuthorizationCodeBearer(AzureAuthorizationCodeBearerBase):
    def __init__(
        self,
        app_client_id: str,
        tenant_id: str,
        scopes: Optional[dict[str, str]] = None,
        token_version: Literal[1, 2] = 2,
        openid_config_use_app_id: bool = False,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings for a single tenant application.

        :param app_client_id: str
            Your applications client ID. This will be the `Web app` in Azure AD
        :param tenant_id: str
            Your Azure tenant ID, only needed for single tenant apps
        :param scopes: Optional[dict[str, str]
            Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }

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
            tenant_id=tenant_id,
            scopes=scopes,
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
        scopes: Optional[dict[str, str]] = None,
        validate_iss: bool = True,
        iss_callable: Optional[Callable[..., Any]] = None,
        openid_config_use_app_id: bool = False,
        openapi_authorization_url: Optional[str] = None,
        openapi_token_url: Optional[str] = None,
        openapi_description: Optional[str] = None,
    ) -> None:
        """
        Initialize settings for a multi-tenant application.

        :param app_client_id: str
            Your applications client ID. This will be the `Web app` in Azure AD
        :param scopes: Optional[dict[str, str]
            Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }

        :param validate_iss: bool
            Whether to validate the token `iss` (issuer) or not. This can be skipped to allow anyone to log in.
        :param iss_callable: Callable
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
            scopes=scopes,
            validate_iss=validate_iss,
            iss_callable=iss_callable,
            multi_tenant=True,
            openid_config_use_app_id=openid_config_use_app_id,
            openapi_authorization_url=openapi_authorization_url,
            openapi_token_url=openapi_token_url,
            openapi_description=openapi_description,
        )
        self.scheme_name: str = 'Azure AD - PKCE, Multi-tenant'
