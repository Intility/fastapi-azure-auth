import pytest
from demo_project.main import app
from fastapi.testclient import TestClient

openapi_schema = {
    'openapi': '3.0.2',
    'info': {
        'title': 'My Project',
        'description': '## Welcome to my API! \n This is my description, written in `markdown`',
        'version': '1.0.0',
    },
    'paths': {
        '/api/v1/hello': {
            'get': {
                'tags': ['hello'],
                'summary': 'Say hello',
                'description': 'Wonder who we say hello to?',
                'operationId': 'helloWorld',
                'responses': {
                    '200': {
                        'description': 'Successful Response',
                        'content': {
                            'application/json': {'schema': {'$ref': '#/components/schemas/HelloWorldResponse'}}
                        },
                    }
                },
                'security': [{'Azure AD - PKCE, Single-tenant': []}],
            }
        },
        '/api/v1/hello-multi-auth': {
            'get': {
                'tags': ['hello'],
                'summary': 'Say hello with an API key',
                'description': 'Wonder how this auth is done?',
                'operationId': 'helloWorldApiKey',
                'responses': {
                    '200': {
                        'description': 'Successful Response',
                        'content': {'application/json': {'schema': {'$ref': '#/components/schemas/TokenType'}}},
                    }
                },
                'security': [{'Azure AD - PKCE, Multi-tenant': []}, {'APIKeyHeader': []}],
            }
        },
    },
    'components': {
        'schemas': {
            'HelloWorldResponse': {
                'title': 'HelloWorldResponse',
                'required': ['hello', 'user'],
                'type': 'object',
                'properties': {
                    'hello': {'title': 'Hello', 'type': 'string', 'description': 'What we\'re saying hello to'},
                    'user': {
                        'title': 'User',
                        'allOf': [{'$ref': '#/components/schemas/User'}],
                        'description': 'The user object',
                    },
                },
            },
            'TokenType': {
                'title': 'TokenType',
                'required': ['api_key', 'azure_auth'],
                'type': 'object',
                'properties': {
                    'api_key': {'title': 'Api Key', 'type': 'boolean', 'description': 'API key was used'},
                    'azure_auth': {'title': 'Azure Auth', 'type': 'boolean', 'description': 'Azure auth was used'},
                },
            },
            'User': {
                'title': 'User',
                'required': ['aud', 'tid', 'claims', 'access_token'],
                'type': 'object',
                'properties': {
                    'aud': {'title': 'Aud', 'type': 'string', 'description': 'Audience'},
                    'tid': {'title': 'Tid', 'type': 'string', 'description': 'Tenant ID'},
                    'roles': {
                        'title': 'Roles',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'Roles (Groups) the user has for this app',
                        'default': [],
                    },
                    'claims': {'title': 'Claims', 'type': 'object', 'description': 'The entire decoded token'},
                    'scp': {'title': 'Scp', 'type': 'string', 'description': 'Scope'},
                    'name': {'title': 'Name', 'type': 'string', 'description': 'Name'},
                    'access_token': {
                        'title': 'Access Token',
                        'type': 'string',
                        'description': 'The access_token. Can be used for fetching the Graph API',
                    },
                },
            },
        },
        'securitySchemes': {
            'Azure AD - PKCE, Single-tenant': {
                'type': 'oauth2',
                'description': '`Leave client_secret blank`',
                'flows': {
                    'authorizationCode': {
                        'scopes': {
                            'api://oauth299-9999-9999-abcd-efghijkl1234567890/user_impersonation': '**No client secret needed, leave blank**'
                        },
                        'authorizationUrl': 'https://login.microsoftonline.com/intility_tenant_id/oauth2/v2.0/authorize',
                        'tokenUrl': 'https://login.microsoftonline.com/intility_tenant_id/oauth2/v2.0/token',
                    }
                },
            },
            'Azure AD - PKCE, Multi-tenant': {
                'description': '`Leave ' 'client_secret ' 'blank`',
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
            'APIKeyHeader': {'type': 'apiKey', 'in': 'header', 'name': 'TEST-API-KEY'},
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
