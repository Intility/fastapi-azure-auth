from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AccessToken(BaseModel):
    aud: str = Field(..., description='Identifies the intended audience of the token.')
    iss: str = Field(
        ...,
        description='Identifies the STS that constructs and returns the token, and the Azure AD tenant of the authenticated user. ',
    )
    idp: Optional[str] = Field(
        default=None,
        description="Records the identity provider that authenticated the subject of the token. Use iss if the claim isn't present.",
    )
    iat: int = Field(..., description='Specifies when the authentication for this token occurred.')
    nbf: int = Field(..., description='Specifies the time after which the JWT can be processed.')
    exp: int = Field(
        ..., description='Specifies the expiration time before which the JWT can be accepted for processing.'
    )
    aio: str = Field(
        ...,
        description="An internal claim used by Azure AD to record data for token reuse. Resources shouldn't use this claim.",
    )
    name: Optional[str] = Field(
        default=None, description='Provides a human-readable value that identifies the subject of the token.'
    )
    scp: str = Field(
        ...,
        description='The set of scopes exposed by the application for which the client application has requested (and received) consent. Only included for user tokens.',
    )
    roles: List[str] = Field(
        default=[],
        description='The set of permissions exposed by the application that the requesting application or user has been given permission to call.',
    )
    wids: Optional[List[str]] = Field(
        default=None,
        description='Denotes the tenant-wide roles assigned to this user, from the section of roles present in Azure AD built-in roles.',
    )
    groups: Optional[List[str]] = Field(
        default=None, description='Provides object IDs that represent the group memberships of the subject.'
    )
    sub: str = Field(..., description='The principal associated with the token.')
    oid: str = Field(
        ...,
        description='The immutable identifier for the requestor, which is the verified identity of the user or service principal',
    )
    tid: str = Field(..., description='Represents the tenant that the user is signing in to')
    uti: str = Field(
        ...,
        description='Token identifier claim, equivalent to jti in the JWT specification. Unique, per-token identifier that is case-sensitive.',
    )
    rh: str = Field(
        ..., description="An internal claim used by Azure to revalidate tokens. Resources shouldn't use this claim."
    )
    ver: Literal['2.0'] = Field(..., description='Indicates the version of the access token.')

    # Optional claims, configured in Azure AD
    acct: Optional[str] = Field(default=None, description="User's account status in tenant")
    auth_time: Optional[str] = Field(
        default=None, description='Time when the user last authenticated; See OpenID Connect spec'
    )
    ctry: Optional[str] = Field(default=None, description="User's country/region")
    email: Optional[str] = Field(default=None, description='The addressable email for this user, if the user has one')
    family_name: Optional[str] = Field(
        default=None,
        description='Provides the last name, surname, or family name of the user as defined in the user object',
    )
    fwd: Optional[str] = Field(default=None, description='IP address')
    given_name: Optional[str] = Field(
        default=None, description='Provides the first or "given" name of the user, as set on the user object'
    )
    idtyp: Optional[str] = Field(default=None, description='Signals whether the token is an app-only token')
    in_corp: Optional[str] = Field(
        default=None,
        description="Signals if the client is logging in from the corporate network; if they're not, the claim isn't included",
    )
    ipaddr: Optional[str] = Field(default=None, description='The IP address the client logged in from')
    login_hint: Optional[str] = Field(default=None, description='Login hint')
    onprem_sid: Optional[str] = Field(default=None, description='On-premises security identifier')
    pwd_exp: Optional[str] = Field(default=None, description='The datetime at which the password expires')
    pwd_url: Optional[str] = Field(default=None, description='A URL that the user can visit to change their password')
    sid: Optional[str] = Field(default=None, description='Session ID, used for per-session user sign out')
    tenant_ctry: Optional[str] = Field(default=None, description="Resource tenant's country/region")
    tenant_region_scope: Optional[str] = Field(default=None, description='Region of the resource tenant')
    upn: Optional[str] = Field(
        default=None,
        description='An identifier for the user that can be used with the username_hint parameter; not a durable identifier for the user and should not be used to key data',
    )
    verified_primary_email: Optional[List[str]] = Field(
        default=None, description="Sourced from the user's PrimaryAuthoritativeEmail"
    )
    verified_secondary_email: Optional[List[str]] = Field(
        default=None, description="Sourced from the user's SecondaryAuthoritativeEmail"
    )
    vnet: Optional[str] = Field(default=None, description='VNET specifier information')
    xms_pdl: Optional[str] = Field(default=None, description='Preferred data location')
    xms_pl: Optional[str] = Field(default=None, description='User-preferred language')
    xms_tpl: Optional[str] = Field(default=None, description='Tenant-preferred language')
    ztdid: Optional[str] = Field(default=None, description='Zero-touch Deployment ID')

    # V1.0 only
    acr: Optional[Literal["0", "1"]] = Field(
        default=None,
        description="Indicates the authentication method used to sign in the user. Only available in V1.0 tokens",
    )
    # V1.0 only
    amr: Optional[List[str]] = Field(
        default=None,
        description="Identifies the authentication method of the subject of the token. Only available in V1.0 tokens",
    )
    # V1.0 only
    appid: Optional[str] = Field(
        default=None,
        description="The application ID of the client using the token. Only available in V1.0 tokens",
    )
    # V1.0 only
    appidacr: Optional[Literal["0", "1", "2"]] = Field(
        default=None,
        description="Indicates authentication method of the client. Only available in V1.0 tokens",
    )
    # V1.0 only
    unique_name: Optional[str] = Field(
        default=None,
        description="Provides a human readable value that identifies the subject of the token. Only available in V1.0 tokens",
    )

    # V2.0 only
    azp: Optional[str] = Field(
        default=None,
        description="The application ID of the client using the token. Only available in V2.0 tokens",
    )
    # V2.0 only
    azpacr: Optional[Literal["0", "1", "2"]] = Field(
        default=None,
        description="Indicates the authentication method of the client. Only available in V2.0 tokens",
    )
    # V2.0 only
    preferred_username: Optional[str] = Field(
        default=None,
        description="The primary username that represents the user. Only available in V2.0 tokens",
    )


class User(AccessToken):
    claims: Dict[Any, Any] = Field(..., description='The entire decoded token')
    access_token: str = Field(..., description='The access_token. Can be used for fetching the Graph API')
    is_guest: bool = Field(False, description='The user is a guest user in the tenant')
