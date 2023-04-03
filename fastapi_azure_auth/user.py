from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, root_validator


class User(BaseModel):
    aud: str = Field(..., description='Audience')
    tid: Optional[str] = Field(default=None, description='Tenant ID')
    roles: List[str] = Field(default=[], description='Roles (Groups) the user has for this app')
    claims: Dict[Any, Any] = Field(..., description='The entire decoded token')
    scp: Optional[str] = Field(default=None, description='Scope')
    name: Optional[str] = Field(default=None, description='Name')
    access_token: str = Field(..., description='The access_token. Can be used for fetching the Graph API')
    is_guest: bool = Field(False, description='The user is a guest user in the tenant')

    @root_validator(pre=True)
    def set_is_guest(cls, values: Dict) -> Dict:
        """
        Ensures that we set the `is_guest` property before model is created.
        """
        # if the user has set up `acct` claim in Azure, that's most efficient. 0 = tenant member, 1 = guest
        if values.get('claims', {}).get('acct') == 1:
            return values | {'is_guest': True}
        # formula: idp exist and idp != iss: guest user
        claims_iss = values.get('claims', {}).get('iss')
        idp = values.get('claims', {}).get('idp', claims_iss)
        return values | {'is_guest': idp != claims_iss}
