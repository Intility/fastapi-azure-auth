from typing import List, Optional, Union

from pydantic import AnyHttpUrl, BaseSettings, Field, HttpUrl, validator


class AzureActiveDirectory(BaseSettings):
    OPENAPI_CLIENT_ID: str = Field(default='', env='OPENAPI_CLIENT_ID')
    APP_CLIENT_ID: str = Field(default='', env='APP_CLIENT_ID')


class Credentials(BaseSettings):
    MY_THIRD_PARTY_PASSWORD: str = Field(default='my_password', env='MY_THIRD_PARTY_PASSWORD')


class Settings(Credentials, AzureActiveDirectory):
    API_V1_STR: str = '/api/v1'
    SECRET_KEY: str = Field(..., env='SECRET_KEY')

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = ['http://localhost:8000']

    @validator('BACKEND_CORS_ORIGINS', pre=True)
    def assemble_cors_origins(cls, value: Union[str, List[str]]) -> Union[List[str], str]:  # pragma: no cover
        """
        Validate cors list
        """
        if isinstance(value, str) and not value.startswith('['):
            return [i.strip() for i in value.split(',')]
        elif isinstance(value, (list, str)):
            return value
        raise ValueError(value)

    PROJECT_NAME: str = 'My Project'
    SENTRY_DSN: Optional[HttpUrl] = None

    @validator('SENTRY_DSN', pre=True)
    def sentry_dsn_can_be_blank(cls, value: str) -> Optional[str]:  # pragma: no cover
        """
        Validate sentry DSN
        """
        if not value:
            return None
        return value

    class Config:  # noqa
        env_file = '.env'
        env_file_encoding = 'utf-8'
        case_sensitive = True


settings = Settings()
