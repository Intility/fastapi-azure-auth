import base64
import json
import time
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes, serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jose import jwt


def generate_key_and_cert():
    signing_key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'NO'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'OSLO'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'OSLO'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Intility AS'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'intility.com'),
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


def build_access_token_azure_not_guest(request):
    issuer = 'https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/'
    return do_build_access_token(request, issuer, tenant_id='intility_tenant_id')


def build_access_token_azure_guest(request):
    issuer = 'https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/'
    return do_build_access_token(request, issuer, tenant_id='guest_tenant_id')


def do_build_access_token(request, tenant_id=None):
    issued_at = int(time.time())
    expires = issued_at + 3600
    claims = {
        'aud': 'api://oauth299-9999-9999-abcd-efghijkl1234567890',
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
    token = jwt.encode(
        claims,
        signing_key_b.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption(),
        ),
        algorithm='RS256',
    )
    response = {
        'resource': 'myfastapiapp',
        'token_type': 'bearer',
        'refresh_token_expires_in': 28799,
        'refresh_token': 'random_refresh_token',
        'expires_in': 3600,
        'id_token': 'not_used',
        'access_token': token,
    }
    return 200, [], json.dumps(response)


def build_openid_keys(empty_keys=False):
    if empty_keys:
        keys = {'keys': []}
    else:
        keys = {
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
                    'kid': 'dummythumbprint',
                    'x5t': 'dummythumbprint',
                    'n': 'somebase64encodedmodulus',
                    'e': 'somebase64encodedexponent',
                    'x5c': [
                        base64.b64encode(signing_cert_b).decode(),
                    ],
                },
            ]
        }
    return keys


signing_key_a, signing_cert_a = generate_key_and_cert()
signing_key_b, signing_cert_b = generate_key_and_cert()
