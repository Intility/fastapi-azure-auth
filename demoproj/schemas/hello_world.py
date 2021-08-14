from pydantic import BaseModel, Field

from fastapi_azure_auth.user import User


class HelloWorldResponse(BaseModel):
    hello: str = Field(..., description='What we\'re saying hello to')
    user: User = Field(..., description='The user object')
