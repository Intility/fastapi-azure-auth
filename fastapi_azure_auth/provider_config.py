import base64
import logging
from datetime import datetime, timedelta
from typing import Optional

from aiohttp import ClientSession
from cryptography.hazmat._types import _PUBLIC_KEY_TYPES as KeyTypes
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.x509 import load_der_x509_certificate
from fastapi import HTTPException, status

log = logging.getLogger('fastapi_azure_auth')


class ProviderConfig:
    def __init__(self) -> None:
        self.tenant_id = '9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6'  # For non-intility apps, you need to change this.
        self._config_timestamp: Optional[datetime] = None

        self.authorization_endpoint: str
        self.signing_keys: list[KeyTypes]
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
                log.debug('Loading Intility Azure ID Provider configuration.')
                await self._load_openid_config()
                self._config_timestamp = datetime.now()
            except Exception as error:
                log.exception('Unable to fetch openid-configuration from Azure AD. Error: %s', error)
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
        config_url = f'https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid-configuration'

        log.info('Trying to get OpenID Connect config from %s', config_url)
        async with ClientSession() as session:
            # Fetch openid config
            async with session.get(config_url, timeout=10) as openid_response:
                openid_response.raise_for_status()
                openid_cfg = await openid_response.json()
                jwks_uri = openid_cfg['jwks_uri']
                # Fetch keys
                async with session.get(jwks_uri, timeout=10) as jwks_response:
                    jwks_response.raise_for_status()
                    keys = await jwks_response.json()
                    signing_certificates = [x['x5c'][0] for x in keys['keys'] if x.get('use', 'sig') == 'sig']
                    self._load_keys(signing_certificates)

        self.authorization_endpoint = openid_cfg['authorization_endpoint']
        self.token_endpoint = openid_cfg['token_endpoint']
        self.end_session_endpoint = openid_cfg['end_session_endpoint']
        self.issuer = openid_cfg['issuer']

    def _load_keys(self, certificates: list[str]) -> None:
        """
        Create certificates based on signing keys and store them
        """
        new_keys = []
        for cert in certificates:
            log.debug('Loading public key from certificate: %s', cert)
            cert_obj = load_der_x509_certificate(base64.b64decode(cert), backend)
            new_keys.append(cert_obj.public_key())
        self.signing_keys = new_keys


provider_config = ProviderConfig()
