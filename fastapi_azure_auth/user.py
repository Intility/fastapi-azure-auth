from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class User(BaseModel):
    aud: str = Field(..., description='Audience')
    tid: str = Field(..., description='Tenant ID')
    given_name: Optional[str] = Field(default=None, description='Given name')
    family_name: Optional[str] = Field(default=None, description='Family name')
    unique_name: Optional[str] = Field(default=None, description='Unique name')
    ipaddr: Optional[IPvAnyAddress] = Field(default=None, description='IP address when token was claimed')
    upn: str = Field(..., description='UPN')
    roles: list[str] = Field(default=[], description='Roles (Groups) the user has for this app')
    claims: dict = Field(..., description='The entire decoded token')
