import logging
from typing import Dict, Optional

from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.requests import Request

from fastapi_azure_auth.provider_config import provider_config

log = logging.getLogger('fastapi_azure_auth')


def invalid_auth(detail: str) -> HTTPException:
    """
    Raise a 401 unauthorized with given detail message.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={'WWW-Authenticate': 'Bearer'},
    )


class AzureAuthorizationCodeBearer(OAuth2AuthorizationCodeBearer):
    def __init__(
        self, app: FastAPI, app_client_id: str, scopes: Optional[Dict[str, str]] = None, allow_guest_users: bool = True
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

    async def __call__(self, request: Request) -> dict:
        """
        Extends call to also validate the token
        """
        access_token = await super().__call__(request=request)
        # Load new config if old
        await provider_config.load_config()
        for index, key in enumerate(provider_config.signing_keys):
            try:
                # Set strict in case defaults change
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
                # Validate token and return claims
                token = jwt.decode(
                    access_token,
                    key=key,
                    algorithms=['RS256'],
                    audience=f'api://{self.app_client_id}',
                    issuer=f'https://sts.windows.net/{provider_config.tenant_id}/',
                    options=options,
                )
                if not self.allow_guest_users and token['tid'] != provider_config.tenant_id:
                    raise invalid_auth(detail='Guest users not allowed')
                return token
            except HTTPException:
                raise
            except JWTClaimsError as error:
                log.info('Token contains invalid claims. %s', error)
                raise invalid_auth(detail='Token contains invalid claims')
            except ExpiredSignatureError as error:
                log.info('Token signature has expired. %s', error)
                raise invalid_auth(detail='Token signature has expired')
            except JWTError as error:
                if str(error) == 'Signature verification failed.' and index < len(provider_config.signing_keys) - 1:
                    continue
                log.warning('Invalid token. Error: %s', error, exc_info=True)
                raise invalid_auth(detail='Unable to validate token')
            except Exception as error:
                # Extra failsafe in case of a bug in a future version of the jwt library
                log.exception('Unable to process jwt token. Uncaught error: %s', error)
                raise invalid_auth(detail='Unable to process token')
        raise invalid_auth(detail='Unable to verify token, no signing keys found')
