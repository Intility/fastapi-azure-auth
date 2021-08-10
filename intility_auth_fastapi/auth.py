import logging
from typing import Dict, Optional

from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from intility_auth_fastapi.provider_config import provider_config
from jose import JWTError, jwt
from starlette.requests import Request

log = logging.getLogger('intility_auth_fastapi')


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
                    issuer='https://sts.windows.net/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/',
                    options=options,
                )
            except JWTError as error:
                if str(error) == 'Signature verification failed.':
                    # Test next key, there can be multiple
                    if index < len(provider_config.signing_keys) - 1:
                        continue
                else:
                    log.warning('Invalid token. Error: %s', error, exc_info=True)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='Could not validate credentials',
                        headers={'WWW-Authenticate': 'Bearer'},
                    )
