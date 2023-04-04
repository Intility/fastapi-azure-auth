import pytest

from fastapi_azure_auth.user import User


@pytest.mark.parametrize(
    'claims, expected',
    (
        [
            {  # v1 appreg
                'iss': 'https://sts.windows.net/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/',
                'idp': 'https://sts.windows.net/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/',
                'ver': '1.0',
            },
            False,
        ],
        [
            {  # v2 appreg
                'iss': 'https://login.microsoftonline.com/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/v2.0',
                'ver': '2.0',
            },
            False,
        ],
        [
            {  # v1 guest user
                'iss': 'https://sts.windows.net/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/',
                'idp': 'https://sts.windows.net/e49ee8b0-4ec8-486f-93f3-bedaa281a154/',
                'ver': '1.0',
            },
            True,
        ],
        [
            {  # v2 guest user
                'iss': 'https://login.microsoftonline.com/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/v2.0',
                'idp': 'https://sts.windows.net/e49ee8b0-4ec8-486f-93f3-bedaa281a154/',
                'ver': '2.0',
            },
            True,
        ],
        [
            {  # v1 tenant member user
                'iss': 'https://sts.windows.net/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/',
                'ver': '1.0',
            },
            False,
        ],
        [
            {  # v1 tenant member user
                'iss': 'https://login.microsoftonline.com/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/v2.0',
                'ver': '2.0',
            },
            False,
        ],
        [
            {  # acct claim
                'acct': 1,  # 1 == guest
            },
            True,
        ],
        [
            {  # acct claim
                'acct': 0,  # 1 == tenant member
            },
            False,
        ],
    ),
    ids=[
        'v1 appreg',
        'v2 appreg',
        'v1 guest user',
        'v2 guest user',
        'v1 tenant member user',
        'v2 tenant member user',
        'acct guest',
        'acct tenant member',
    ],
)
def test_guest_user(claims: dict[str, str], expected: bool):
    user = User(aud='aud', tid='tid', roles=[], claims=claims, scp=None, name='name', access_token='access_token')
    assert user.is_guest == expected
