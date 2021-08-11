import logging
from typing import Dict, Optional

from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from starlette.requests import Request

from intility_auth_fastapi.provider_config import provider_config

log = logging.getLogger('intility_auth_fastapi')


def invalid_auth(detail: str) -> HTTPException:
    """
    Raise a 401 unauthorized with given detail message.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={'WWW-Authenticate': 'Bearer'},
    )


class IntilityAuthorizationCodeBearer(OAuth2AuthorizationCodeBearer):
    def __init__(
        self,
        app: FastAPI,
        app_client_id: str,
        scopes: Optional[Dict[str, str]] = None,
    ) -> None:
        self.app_client_id = app_client_id

        @app.on_event('startup')
        async def load_config() -> None:
            """
            Load config on startup.
            """
            await provider_config.load_config()

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
                    'require_nbf': False,
                    'require_iss': True,
                    'require_sub': True,
                    'require_jti': False,
                    'require_at_hash': False,
                    'leeway': 0,
                }

                # Validate token and return claims
                return jwt.decode(
                    access_token,
                    key=key,
                    algorithms=['RS256'],
                    audience=f'api://{self.app_client_id}',
                    issuer=f'https://sts.windows.net/{provider_config.tenant_id}/',
                    options=options,
                )
            except JWTClaimsError as error:
                log.info('Token contains invalid claims. %s', error)
                raise invalid_auth(detail='Toke contains invalid claims')
            except ExpiredSignatureError as error:
                log.info('Token signature has expired. %s', error)
                raise invalid_auth(detail='Token signature has expired')
            except JWTError as error:
                if str(error) == 'Signature verification failed.' and index < len(provider_config.signing_keys) - 1:
                    continue
                log.warning('Invalid token. Error: %s', error, exc_info=True)
                raise invalid_auth(detail='Unable to validate token')
            except Exception as error:
                log.exception('Unable to process jwt token. Uncaught error: %s', error)
                raise invalid_auth(detail='Unable to process token')
