import base64
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from aiohttp import ClientSession
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.types import PUBLIC_KEY_TYPES as KeyTypes
from cryptography.x509 import load_der_x509_certificate
from fastapi import HTTPException, status

log = logging.getLogger('fastapi_azure_auth')


class OpenIdConfig:
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        multi_tenant: bool = False,
        token_version: int = 2,
        app_id: Optional[str] = None,
    ) -> None:
        self.tenant_id: Optional[str] = tenant_id
        self._config_timestamp: Optional[datetime] = None
        self.multi_tenant: bool = multi_tenant
        self.token_version: int = token_version
        self.app_id = app_id

        self.authorization_endpoint: str
        self.signing_keys: dict[str, KeyTypes]
        self.token_endpoint: str
        self.end_session_endpoint: str
        self.issuer: str

    async def load_config(self) -> None:
        """
        Loads config from the Intility openid-config endpoint if it's over 24 hours old (or don't exist)
        """
        refresh_time = datetime.now() - timedelta(hours=24)
        if not self._config_timestamp or self._config_timestamp < refresh_time:
            try:
                log.debug('Loading Azure AD OpenID configuration.')
                await self._load_openid_config()
                self._config_timestamp = datetime.now()
            except Exception as error:
                log.exception('Unable to fetch OpenID configuration from Azure AD. Error: %s', error)
                # We can't fetch an up to date openid-config, so authentication will not work.
                if self._config_timestamp:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='Connection to Azure AD is down. Unable to fetch provider configuration',
                        headers={'WWW-Authenticate': 'Bearer'},
                    )
                else:
                    raise RuntimeError(f'Unable to fetch provider information. {error}')

            log.info('fastapi-azure-auth loaded settings from Azure AD.')
            log.info('authorization endpoint: %s', self.authorization_endpoint)
            log.info('token endpoint:         %s', self.token_endpoint)
            log.info('end session endpoint:   %s', self.end_session_endpoint)
            log.info('issuer:                 %s', self.issuer)

    async def _load_openid_config(self) -> None:
        """
        Load openid config, fetch signing keys
        """
        path = 'common' if self.multi_tenant else self.tenant_id

        if self.token_version == 2:
            config_url = f'https://login.microsoftonline.com/{path}/v2.0/.well-known/openid-configuration'
        else:
            config_url = f'https://login.microsoftonline.com/{path}/.well-known/openid-configuration'
        if self.app_id:
            config_url += f'?appid={self.app_id}'

        log.info('Trying to get OpenID Connect config from %s', config_url)
        async with ClientSession() as session:
            # Fetch openid config
            async with session.get(config_url, timeout=10) as openid_response:
                openid_response.raise_for_status()
                openid_cfg = await openid_response.json()
                jwks_uri = openid_cfg['jwks_uri']
                # Fetch keys
                log.info('Fetching jwks from %s', jwks_uri)
                async with session.get(jwks_uri, timeout=10) as jwks_response:
                    jwks_response.raise_for_status()
                    keys = await jwks_response.json()
                    self._load_keys(keys['keys'])

        self.authorization_endpoint = openid_cfg['authorization_endpoint']
        self.token_endpoint = openid_cfg['token_endpoint']
        self.end_session_endpoint = openid_cfg['end_session_endpoint']
        self.issuer = openid_cfg['issuer']

    def _load_keys(self, keys: list[dict[str, Any]]) -> None:
        """
        Create certificates based on signing keys and store them
        """
        self.signing_keys = {}
        for key in keys:
            if key.get('use') == 'sig':  # Only care about keys that are used for signatures, not encryption
                log.debug('Loading public key from certificate: %s', key)
                cert_obj = load_der_x509_certificate(base64.b64decode(key['x5c'][0]), backend)
                if kid := key.get('kid'):  # In case a key would not have a thumbprint we can match, we don't want it.
                    self.signing_keys[kid] = cert_obj.public_key()
