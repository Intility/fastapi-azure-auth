import base64
import json
import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.requests import Request

from fastapi_azure_auth.provider_config import provider_config
from fastapi_azure_auth.user import User

log = logging.getLogger('fastapi_azure_auth')


class InvalidAuth(HTTPException):
    """
    Exception raised when the user is not authorized
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={'WWW-Authenticate': 'Bearer'}
        )


class GuestUserException(Exception):
    """
    Exception raised when a guest user attempts to access, but the
    `allow_guest_users` setting is set to `False`
    """

    pass


class AzureAuthorizationCodeBearer(OAuth2AuthorizationCodeBearer):
    def __init__(
        self,
        app: FastAPI,
        app_client_id: str,
        scopes: Optional[Dict[str, str]] = None,
        allow_guest_users: bool = True,
        attach_user_to_request: bool = True,
    ) -> None:
        """
        Initialize settings.

        :param app: Your FastAPI app.
        :param app_client_id: Client ID for this app (not your SPA)
        :param scopes: Scopes, these are the ones you've configured in Azure AD. Key is scope, value is a description.
            Example:
                {
                    f'api://{settings.APP_CLIENT_ID}/user_impersonation': 'user impersonation'
                }
        :param allow_guest_users: Guest users in the tenant can by default access this app,
                                  unless service principals are set up. This setting allow you to deny this behaviour.
        """
        self.app_client_id: str = app_client_id
        self.allow_guest_users: bool = allow_guest_users

        @app.on_event('startup')
        async def load_config() -> None:
            """
            Load config on startup.
            """
            await provider_config.load_config()  # pragma: no cover

        super().__init__(
            authorizationUrl=f'https://login.microsoftonline.com/{provider_config.tenant_id}/oauth2/v2.0/authorize',
            tokenUrl=f'https://login.microsoftonline.com/{provider_config.tenant_id}/oauth2/v2.0/token',
            scopes=scopes,
            description='`Leave client_secret blank`',
        )

    async def __call__(self, request: Request) -> dict[str, Any]:
        """
        Extends call to also validate the token
        """
        access_token = await super().__call__(request=request)
        try:
            # Extract header information of the token.
            header = json.loads(base64.b64decode(access_token.split('.')[0]))  # header, claims, signature
        except Exception as error:
            log.warning('Malformed token received. %s. Error: %s', access_token, error, exc_info=True)
            raise InvalidAuth(detail='Invalid token format')

        # Load new config if old
        await provider_config.load_config()

        # Use the `kid` from the header to find a matching signing key to use
        if key := provider_config.signing_keys.get(header.get('kid')):
            try:
                # We require and validate all fields in an Azure AD token
                options = {
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_iat': True,
                    'verify_exp': True,
                    'verify_nbf': True,
                    'verify_iss': True,
                    'verify_sub': True,
                    'verify_jti': True,
                    'verify_at_hash': True,
                    'require_aud': True,
                    'require_iat': True,
                    'require_exp': True,
                    'require_nbf': True,
                    'require_iss': True,
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
                    audience=f'api://{self.app_client_id}',
                    issuer=f'https://sts.windows.net/{provider_config.tenant_id}/',
                    options=options,
                )
                if not self.allow_guest_users and token['tid'] != provider_config.tenant_id:
                    raise GuestUserException()
                # Attach the user to the request. Can be accessed through `request.state.user`
                user: User = User(**token | {'claims': token})
                request.state.user = user
                return token
            except GuestUserException:
                raise InvalidAuth('Guest users not allowed')
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
        raise InvalidAuth(detail='Unable to verify token, no signing keys found')
