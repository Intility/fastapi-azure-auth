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
                'properties': {
                    'access_token': {
                        'description': 'The access_token. Can be used for fetching the Graph API',
                        'title': 'Access Token',
                        'type': 'string',
                    },
                    'aud': {'description': 'Audience', 'title': 'Aud', 'type': 'string'},
                    'claims': {'description': 'The entire decoded token', 'title': 'Claims', 'type': 'object'},
                    'is_guest': {
                        'default': False,
                        'description': 'The user is a guest user in the tenant',
                        'title': 'Is Guest',
                        'type': 'boolean',
                    },
                    'name': {'description': 'Name', 'title': 'Name', 'type': 'string'},
                    'oid': {
                        'description': 'Immutable ' 'identifier ' 'for ' 'the ' 'requestor',
                        'title': 'Oid',
                        'type': 'string',
                    },
                    'roles': {
                        'default': [],
                        'description': 'Roles (Groups) the user has for this app',
                        'items': {'type': 'string'},
                        'title': 'Roles',
                        'type': 'array',
                    },
                    'scp': {'description': 'Scope', 'title': 'Scp', 'type': 'string'},
                    'sub': {
                        'description': 'Principal ' 'associated ' 'with ' 'the ' 'token.',
                        'title': 'Sub',
                        'type': 'string',
                    },
                    'tid': {'description': 'Tenant ID', 'title': 'Tid', 'type': 'string'},
                },
                'required': ['aud', 'claims', 'access_token', 'sub', 'oid'],
                'title': 'User',
                'type': 'object',
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
