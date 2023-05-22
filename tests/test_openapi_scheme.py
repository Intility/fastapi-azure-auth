import fastapi
import pytest
from demo_project.main import app
from fastapi.testclient import TestClient

openapi_schema = {
    'components': {
        'schemas': {
            'HelloWorldResponse': {
                'properties': {
                    'hello': {
                        'description': "What we're saying hello to",
                        'title': 'Hello',
                        'type': 'string',
                    },
                    'user': {
                        'allOf': [{'$ref': '#/components/schemas/User'}],
                        'description': 'The user object',
                        'title': 'User',
                    },
                },
                'required': ['hello', 'user'],
                'title': 'HelloWorldResponse',
                'type': 'object',
            },
            'TokenType': {
                'properties': {
                    'api_key': {'description': 'API key was used', 'title': 'Api Key', 'type': 'boolean'},
                    'azure_auth': {
                        'description': 'Azure auth was used',
                        'title': 'Azure Auth',
                        'type': 'boolean',
                    },
                },
                'required': ['api_key', 'azure_auth'],
                'title': 'TokenType',
                'type': 'object',
            },
            'User': {
                'title': 'User',
                'required': [
                    'aud',
                    'iss',
                    'iat',
                    'nbf',
                    'exp',
                    'aio',
                    'sub',
                    'oid',
                    'tid',
                    'uti',
                    'rh',
                    'ver',
                    'claims',
                    'access_token',
                ],
                'type': 'object',
                'properties': {
                    'aud': {
                        'title': 'Aud',
                        'type': 'string',
                        'description': 'Identifies the intended audience of the token. In v2.0 tokens, this value is always the client ID of the API. In v1.0 tokens, it can be the client ID or the resource URI used in the request.',
                    },
                    'iss': {
                        'title': 'Iss',
                        'type': 'string',
                        'description': 'Identifies the STS that constructs and returns the token, and the Azure AD tenant of the authenticated user. If the token issued is a v2.0 token (see the ver claim), the URI ends in /v2.0.',
                    },
                    'idp': {
                        'title': 'Idp',
                        'type': 'string',
                        'description': 'Records the identity provider that authenticated the subject of the token. This value is identical to the value of the Issuer claim unless the user account is not in the same tenant as the issuer, such as guests. Use the value of iss if the claim is not present.',
                    },
                    'iat': {
                        'title': 'Iat',
                        'type': 'integer',
                        'description': 'Specifies when the authentication for this token occurred.',
                    },
                    'nbf': {
                        'title': 'Nbf',
                        'type': 'integer',
                        'description': 'Specifies the time after which the JWT can be processed.',
                    },
                    'exp': {
                        'title': 'Exp',
                        'type': 'integer',
                        'description': 'Specifies the expiration time before which the JWT can be accepted for processing.',
                    },
                    'aio': {
                        'title': 'Aio',
                        'type': 'string',
                        'description': 'An internal claim used by Azure AD to record data for token reuse. Resources should not use this claim.',
                    },
                    'name': {
                        'title': 'Name',
                        'type': 'string',
                        'description': 'Provides a human-readable value that identifies the subject of the token.',
                    },
                    'scp': {
                        'title': 'Scp',
                        'type': 'array',
                        'description': 'The set of scopes exposed by the application for which the client application has requested (and received) consent. Only included for user tokens.',
                        'default': [],
                        'items': {'type': 'string'},
                    },
                    'roles': {
                        'title': 'Roles',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'The set of permissions exposed by the application that the requesting application or user has been given permission to call.',
                        'default': [],
                    },
                    'wids': {
                        'default': [],
                        'title': 'Wids',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'Denotes the tenant-wide roles assigned to this user, from the section of roles present in Azure AD built-in roles.',
                    },
                    'groups': {
                        'default': [],
                        'title': 'Groups',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'Provides object IDs that represent the group memberships of the subject.',
                    },
                    'sub': {
                        'title': 'Sub',
                        'type': 'string',
                        'description': 'The principal associated with the token.',
                    },
                    'oid': {
                        'title': 'Oid',
                        'type': 'string',
                        'description': 'The immutable identifier for the requestor, which is the verified identity of the user or service principal',
                    },
                    'tid': {
                        'title': 'Tid',
                        'type': 'string',
                        'description': 'Represents the tenant that the user is signing in to',
                    },
                    'uti': {
                        'title': 'Uti',
                        'type': 'string',
                        'description': 'Token identifier claim, equivalent to jti in the JWT specification. Unique, per-token identifier that is case-sensitive.',
                    },
                    'rh': {
                        'title': 'Rh',
                        'type': 'string',
                        'description': 'An internal claim used by Azure to revalidate tokens. Resources should not use this claim.',
                    },
                    'ver': {
                        'title': 'Ver',
                        'enum': ['1.0', '2.0'],
                        'type': 'string',
                        'description': 'Indicates the version of the access token.',
                    },
                    'acct': {'title': 'Acct', 'type': 'string', 'description': "User's account status in tenant"},
                    'auth_time': {
                        'title': 'Auth Time',
                        'type': 'string',
                        'description': 'Time when the user last authenticated; See OpenID Connect spec',
                    },
                    'ctry': {'title': 'Ctry', 'type': 'string', 'description': "User's country/region"},
                    'email': {
                        'title': 'Email',
                        'type': 'string',
                        'description': 'The addressable email for this user, if the user has one',
                    },
                    'family_name': {
                        'title': 'Family Name',
                        'type': 'string',
                        'description': 'Provides the last name, surname, or family name of the user as defined in the user object',
                    },
                    'fwd': {'title': 'Fwd', 'type': 'string', 'description': 'IP address'},
                    'given_name': {
                        'title': 'Given Name',
                        'type': 'string',
                        'description': "Provides the first or \"given\" name of the user, as set on the user object",
                    },
                    'idtyp': {
                        'title': 'Idtyp',
                        'type': 'string',
                        'description': 'Signals whether the token is an app-only token',
                    },
                    'in_corp': {
                        'title': 'In Corp',
                        'type': 'string',
                        'description': 'Signals if the client is logging in from the corporate network; if they are not, the claim is not included',
                    },
                    'ipaddr': {
                        'title': 'Ipaddr',
                        'type': 'string',
                        'description': 'The IP address the user authenticated from.',
                    },
                    'login_hint': {'title': 'Login Hint', 'type': 'string', 'description': 'Login hint'},
                    'onprem_sid': {
                        'title': 'Onprem Sid',
                        'type': 'string',
                        'description': 'On-premises security identifier',
                    },
                    'pwd_exp': {
                        'title': 'Pwd Exp',
                        'type': 'string',
                        'description': 'The datetime at which the password expires',
                    },
                    'pwd_url': {
                        'title': 'Pwd Url',
                        'type': 'string',
                        'description': 'A URL that the user can visit to change their password',
                    },
                    'sid': {
                        'title': 'Sid',
                        'type': 'string',
                        'description': 'Session ID, used for per-session user sign out',
                    },
                    'tenant_ctry': {
                        'title': 'Tenant Ctry',
                        'type': 'string',
                        'description': "Resource tenant's country/region",
                    },
                    'tenant_region_scope': {
                        'title': 'Tenant Region Scope',
                        'type': 'string',
                        'description': 'Region of the resource tenant',
                    },
                    'upn': {
                        'title': 'Upn',
                        'type': 'string',
                        'description': 'An identifier for the user that can be used with the username_hint parameter; not a durable identifier for the user and should not be used to key data',
                    },
                    'verified_primary_email': {
                        'default': [],
                        'title': 'Verified Primary Email',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': "Sourced from the user's PrimaryAuthoritativeEmail",
                    },
                    'verified_secondary_email': {
                        'default': [],
                        'title': 'Verified Secondary Email',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': "Sourced from the user's SecondaryAuthoritativeEmail",
                    },
                    'vnet': {'title': 'Vnet', 'type': 'string', 'description': 'VNET specifier information'},
                    'xms_pdl': {'title': 'Xms Pdl', 'type': 'string', 'description': 'Preferred data location'},
                    'xms_pl': {'title': 'Xms Pl', 'type': 'string', 'description': 'User-preferred language'},
                    'xms_tpl': {'title': 'Xms Tpl', 'type': 'string', 'description': 'Tenant-preferred language'},
                    'ztdid': {'title': 'Ztdid', 'type': 'string', 'description': 'Zero-touch Deployment ID'},
                    'acr': {
                        'title': 'Acr',
                        'enum': ['0', '1'],
                        'type': 'string',
                        'description': "A value of 0 for the \"Authentication context class\" claim indicates the end-user authentication did not meet the requirements of ISO/IEC 29115. Only available in V1.0 tokens",
                    },
                    'amr': {
                        'default': [],
                        'title': 'Amr',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'Identifies the authentication method of the subject of the token. Only available in V1.0 tokens',
                    },
                    'appid': {
                        'title': 'Appid',
                        'type': 'string',
                        'description': 'The application ID of the client using the token. Only available in V1.0 tokens',
                    },
                    'appidacr': {
                        'title': 'Appidacr',
                        'enum': ['0', '1', '2'],
                        'type': 'string',
                        'description': 'Indicates authentication method of the client. Only available in V1.0 tokens',
                    },
                    'unique_name': {
                        'title': 'Unique Name',
                        'type': 'string',
                        'description': 'Provides a human readable value that identifies the subject of the token. Only available in V1.0 tokens',
                    },
                    'azp': {
                        'title': 'Azp',
                        'type': 'string',
                        'description': 'The application ID of the client using the token. Only available in V2.0 tokens',
                    },
                    'azpacr': {
                        'title': 'Azpacr',
                        'enum': ['0', '1', '2'],
                        'type': 'string',
                        'description': 'Indicates the authentication method of the client. Only available in V2.0 tokens',
                    },
                    'preferred_username': {
                        'title': 'Preferred Username',
                        'type': 'string',
                        'description': 'The primary username that represents the user. Only available in V2.0 tokens',
                    },
                    'claims': {'title': 'Claims', 'type': 'object', 'description': 'The entire decoded token'},
                    'access_token': {
                        'title': 'Access Token',
                        'type': 'string',
                        'description': 'The access_token. Can be used for fetching the Graph API',
                    },
                    'is_guest': {
                        'title': 'Is Guest',
                        'type': 'boolean',
                        'description': 'The user is a guest user in the tenant',
                        'default': False,
                    },
                },
                'description': 'A more complete overview of the claims available in an access token can be found here:\nhttps://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims',
            },
        },
        'securitySchemes': {
            'APIKeyHeader': {'in': 'header', 'name': 'TEST-API-KEY', 'type': 'apiKey'},
            'Azure AD - PKCE, B2C Multi-tenant': {
                'description': '`Leave client_secret blank`',
                'flows': {
                    'authorizationCode': {
                        'authorizationUrl': 'https://dummy.com/',
                        'scopes': {
                            'api://oauth299-9999-9999-abcd-efghijkl1234567890/user_impersonation': 'User '
                            'impersonation'
                        },
                        'tokenUrl': 'https://dummy.com/',
                    }
                },
                'type': 'oauth2',
            },
            'Azure AD - PKCE, Multi-tenant': {
                'description': '`Leave client_secret blank`',
                'flows': {
                    'authorizationCode': {
                        'authorizationUrl': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                        'scopes': {
                            'api://oauth299-9999-9999-abcd-efghijkl1234567890/user_impersonation': 'User '
                            'impersonation'
                        },
                        'tokenUrl': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                    }
                },
                'type': 'oauth2',
            },
            'Azure AD - PKCE, Single-tenant': {
                'description': '`Leave client_secret blank`',
                'flows': {
                    'authorizationCode': {
                        'authorizationUrl': 'https://login.microsoftonline.com/intility_tenant_id/oauth2/v2.0/authorize',
                        'scopes': {
                            'api://oauth299-9999-9999-abcd-efghijkl1234567890/user_impersonation': '**No '
                            'client '
                            'secret '
                            'needed, '
                            'leave '
                            'blank**'
                        },
                        'tokenUrl': 'https://login.microsoftonline.com/intility_tenant_id/oauth2/v2.0/token',
                    }
                },
                'type': 'oauth2',
            },
        },
    },
    'info': {
        'description': '## Welcome to my API! \n This is my description, written in `markdown`',
        'title': 'My Project',
        'version': '1.0.0',
    },
    'openapi': '3.0.2',
    'paths': {
        '/api/v1/hello': {
            'get': {
                'description': 'Wonder who we say hello to?',
                'operationId': 'helloWorld',
                'responses': {
                    '200': {
                        'content': {
                            'application/json': {'schema': {'$ref': '#/components/schemas/HelloWorldResponse'}}
                        },
                        'description': 'Successful Response',
                    }
                },
                'security': [{'Azure AD - PKCE, Single-tenant': []}, {'Azure AD - PKCE, Single-tenant': []}],
                'summary': 'Say hello',
                'tags': ['hello'],
            }
        },
        '/api/v1/hello-graph': {
            'get': {
                'description': 'An example on how '
                'to use "on behalf '
                'of"-flow to fetch a '
                'graph token and '
                'then fetch data '
                'from graph.',
                'operationId': 'helloGraph',
                'responses': {
                    '200': {
                        'content': {'application/json': {'schema': {'title': 'Response Hellograph'}}},
                        'description': 'Successful Response',
                    }
                },
                'security': [{'Azure AD - PKCE, Single-tenant': []}],
                'summary': 'Fetch graph API using OBO',
                'tags': ['graph'],
            }
        },
        '/api/v1/hello-multi-auth': {
            'get': {
                'description': 'Wonder how this auth is done?',
                'operationId': 'helloWorldApiKey',
                'responses': {
                    '200': {
                        'content': {'application/json': {'schema': {'$ref': '#/components/schemas/TokenType'}}},
                        'description': 'Successful Response',
                    }
                },
                'security': [{'Azure AD - PKCE, Multi-tenant': []}, {'APIKeyHeader': []}],
                'summary': 'Say hello with an API key',
                'tags': ['hello'],
            }
        },
        '/api/v1/hello-multi-auth-b2c': {
            'get': {
                'description': 'Wonder how this auth is done?',
                'operationId': 'helloWorldApiKey',
                'responses': {
                    '200': {
                        'content': {'application/json': {'schema': {'$ref': '#/components/schemas/TokenType'}}},
                        'description': 'Successful Response',
                    }
                },
                'security': [{'Azure AD - PKCE, B2C Multi-tenant': []}, {'APIKeyHeader': []}],
                'summary': 'Say hello with an API key',
                'tags': ['hello'],
            }
        },
    },
}


@pytest.fixture
def test_client():
    """
    Test client that does not run startup event.
    All these tests fails before we get to loading the OpenID Connect configuration.
    """
    yield TestClient(app=app)


@pytest.mark.skipif(fastapi.__version__ < ('0.89.0'), reason='Different schema in older version')
def test_openapi_schema(test_client):
    response = test_client.get('api/v1/openapi.json')
    assert response.status_code == 200, response.text
    assert response.json() == openapi_schema


def test_no_token(test_client):
    response = test_client.get('/api/v1/hello')
    assert response.status_code == 401, response.text
    assert response.json() == {'detail': 'Not authenticated'}


def test_incorrect_token(test_client):
    response = test_client.get('/api/v1/hello', headers={'Authorization': 'Non-existent testtoken'})
    assert response.status_code == 401, response.text
    assert response.json() == {'detail': 'Not authenticated'}


def test_token(test_client):
    response = test_client.get('/api/v1/hello', headers={'Authorization': 'Bearer '})
    assert response.status_code == 401, response.text
    assert response.json() == {'detail': 'Invalid token format'}
