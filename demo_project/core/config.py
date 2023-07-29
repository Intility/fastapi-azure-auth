from typing import List, Optional, Union

import pydantic
from pydantic import AnyHttpUrl, Field, HttpUrl

if pydantic.VERSION.startswith('1.'):
    from pydantic import BaseSettings
else:
    from pydantic_settings import BaseSettings


class AzureActiveDirectory(BaseSettings):  # type: ignore[misc, valid-type]
    OPENAPI_CLIENT_ID: str = Field(default='', env='OPENAPI_CLIENT_ID')
    TENANT_ID: str = Field(default='', env='TENANT_ID')
    APP_CLIENT_ID: str = Field(default='', env='APP_CLIENT_ID')
    AUTH_URL: AnyHttpUrl = Field(default='https://dummy.com/', env='AUTH_URL')
    CONFIG_URL: AnyHttpUrl = Field(default='https://dummy.com/', env='CONFIG_URL')
    TOKEN_URL: AnyHttpUrl = Field(default='https://dummy.com/', env='TOKEN_URL')
    GRAPH_SECRET: str = Field(default='', env='GRAPH_SECRET')
    CLIENT_SECRET: str = Field(default='', env='CLIENT_SECRET')


class Settings(AzureActiveDirectory):
    API_V1_STR: str = '/api/v1'

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[Union[str, AnyHttpUrl]] = ['http://localhost:8000']

    PROJECT_NAME: str = 'My Project'
    SENTRY_DSN: Optional[HttpUrl] = None

    class Config:  # noqa
        env_file = 'demo_project/.env'
        env_file_encoding = 'utf-8'
        case_sensitive = True


settings = Settings()
