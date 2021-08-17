import base64
import time
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes, serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jose import jwt


def generate_key_and_cert():
    """
    Generate a private key and signing cert. We'll use the signing key to sign the JWT token
    and the signing certs will be used to mock the `keys` endpoint in Azure.
    """
    signing_key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'NO'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'OSLO'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'OSLO'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Intility AS'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'intility.no'),
        ]
    )
    signing_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(signing_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.utcnow()
            + timedelta(days=10)
            # Sign our certificate with our private key
        )
        .sign(signing_key, hashes.SHA256(), crypto_default_backend())
        .public_bytes(crypto_serialization.Encoding.DER)
    )
    return signing_key, signing_cert


def build_access_token():
    """
    Build an access token, coming from the tenant ID we expect
    """
    return do_build_access_token(tenant_id='intility_tenant_id')


def build_evil_access_token():
    """
    Build an access token, coming from the tenant ID we expect
    """
    return do_build_access_token(tenant_id='intility_tenant_id', evil=True)


def build_access_token_guest():
    """
    Build an access token, but as a guest user.
    """
    return do_build_access_token(tenant_id='guest_tenant_id')


def build_access_token_invalid_claims():
    """
    Build an access token, coming from the tenant ID we expect
    """
    return do_build_access_token(tenant_id='intility_tenant_id', aud='Jonas')


def build_access_token_expired():
    """
    Build an access token, coming from the tenant ID we expect
    """
    return do_build_access_token(tenant_id='intility_tenant_id', expired=True)


def do_build_access_token(tenant_id=None, aud=None, expired=False, evil=False):
    """
    Build the access token and encode it with the signing key.
    """

    issued_at = int(time.time())
    expires = issued_at - 1 if expired else issued_at + 3600
    claims = {
        'aud': aud or 'api://oauth299-9999-9999-abcd-efghijkl1234567890',
        'iss': 'https://sts.windows.net/intility_tenant_id/',
        'iat': issued_at,
        'exp': expires,
        'nbf': issued_at,
        'acr': '1',
        'aio': 'hello',
        'amr': ['pwd'],
        'appid': '11111111-1111-1111-1111-111111111111',
        'appidacr': '0',
        'family_name': 'Krüger Svensson',
        'given_name': 'Jonas',
        'in_corp': 'true',
        'ipaddr': '192.168.0.0',
        'name': 'Jonas Krüger Svensson / Intility AS',
        'oid': '22222222-2222-2222-2222-222222222222',
        'onprem_sid': 'S-1-2-34-5678901234-5678901234-456789012-34567',
        'rh': '0.hellomylittletokenfriendwhatsupwi-thyoutodayheheiho.',
        'scp': 'user_impersonation',
        'sub': '5ZGASZqgF1taj9GlxDHOpeIJjWlyZJwD3mnZBoz9XVc',
        'tid': tenant_id,
        'unique_name': 'jonas',
        'upn': 'jonas@cool',
        'uti': 'abcdefghijkl-mnopqrstu',
        'ver': '1.0',
    }
    signing_key = signing_key_a if evil else signing_key_b
    return jwt.encode(
        claims,
        signing_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption(),
        ),
        algorithm='RS256',
        headers={'kid': 'real thumbprint', 'x5t': 'another thumbprint'},
    )


def build_openid_keys(empty_keys=False, no_valid_keys=False):
    """
    Build OpenID keys which we'll host at https://login.microsoftonline.com/common/discovery/keys
    """
    if empty_keys:
        return {'keys': []}
    elif no_valid_keys:
        return {
            'keys': [
                {  # this key is not used
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'dummythumbprint',
                    'x5t': 'dummythumbprint',
                    'n': 'somebase64encodedmodulus',
                    'e': 'somebase64encodedexponent',
                    'x5c': [
                        base64.b64encode(signing_cert_a).decode(),
                    ],
                },
            ]
        }
    else:
        return {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'dummythumbprint',
                    'x5t': 'dummythumbprint',
                    'n': 'somebase64encodedmodulus',
                    'e': 'somebase64encodedexponent',
                    'x5c': [
                        base64.b64encode(signing_cert_a).decode(),
                    ],
                },
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'real thumbprint',
                    'x5t': 'real thumbprint2',
                    'n': 'somebase64encodedmodulus',
                    'e': 'somebase64encodedexponent',
                    'x5c': [
                        base64.b64encode(signing_cert_b).decode(),
                    ],
                },
            ]
        }


def openid_configuration():
    return {
        'token_endpoint': 'https://login.microsoftonline.com/intility_tenant_id/token',
        'token_endpoint_auth_methods_supported': [
            'client_secret_post',
            'private_key_jwt',
            'client_secret_basic',
        ],
        'jwks_uri': 'https://login.microsoftonline.com/common/discovery/keys',
        'response_modes_supported': ['query', 'fragment', 'form_post'],
        'subject_types_supported': ['pairwise'],
        'id_token_signing_alg_values_supported': ['RS256'],
        'response_types_supported': ['code', 'id_token', 'code id_token', 'token id_token', 'token'],
        'scopes_supported': ['openid'],
        'issuer': 'https://sts.windows.net/intility_tenant_id/',
        'microsoft_multi_refresh_token': True,
        'authorization_endpoint': 'https://login.microsoftonline.com/intility_tenant_idoauth2/authorize',
        'device_authorization_endpoint': 'https://login.microsoftonline.com/intility_tenant_idoauth2/devicecode',
        'http_logout_supported': True,
        'frontchannel_logout_supported': True,
        'end_session_endpoint': 'https://login.microsoftonline.com/intility_tenant_idoauth2/logout',
        'claims_supported': [
            'sub',
            'iss',
            'cloud_instance_name',
            'cloud_instance_host_name',
            'cloud_graph_host_name',
            'msgraph_host',
            'aud',
            'exp',
            'iat',
            'auth_time',
            'acr',
            'amr',
            'nonce',
            'email',
            'given_name',
            'family_name',
            'nickname',
        ],
        'check_session_iframe': 'https://login.microsoftonline.com/intility_tenant_idoauth2/checksession',
        'userinfo_endpoint': 'https://login.microsoftonline.com/intility_tenant_idopenid/userinfo',
        'kerberos_endpoint': 'https://login.microsoftonline.com/intility_tenant_idkerberos',
        'tenant_region_scope': 'EU',
        'cloud_instance_name': 'microsoftonline.com',
        'cloud_graph_host_name': 'graph.windows.net',
        'msgraph_host': 'graph.microsoft.com',
        'rbac_url': 'https://pas.windows.net',
    }


signing_key_a, signing_cert_a = generate_key_and_cert()
signing_key_b, signing_cert_b = generate_key_and_cert()
