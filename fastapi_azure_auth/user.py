from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class User(BaseModel):
    aud: str = Field(..., description='Audience')
    tid: Optional[str] = Field(default=None, description='Tenant ID')
    roles: List[str] = Field(default=[], description='Roles (Groups) the user has for this app')
    claims: Dict[Any, Any] = Field(..., description='The entire decoded token')
    scp: Optional[str] = Field(default=None, description='Scope')
    name: Optional[str] = Field(default=None, description='Name')
    access_token: str = Field(..., description='The access_token. Can be used for fetching the Graph API')
