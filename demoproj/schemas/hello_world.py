from pydantic import BaseModel, Field


class HelloWorldResponse(BaseModel):
    hello: str = Field(..., description='What we\'re saying hello to')
