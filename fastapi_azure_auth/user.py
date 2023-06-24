from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, validator


class Claims(BaseModel):
    """
    A more complete overview of the claims available in an access token can be found here:
    https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims
    """

    aud: str = Field(
        ...,
        description='Identifies the intended audience of the token. In v2.0 tokens, this value is always the client ID'
        ' of the API. In v1.0 tokens, it can be the client ID or the resource URI used in the request.',
    )
    iss: str = Field(
        ...,
        description='Identifies the STS that constructs and returns the token, and the Azure AD tenant of the'
        ' authenticated user. If the token issued is a v2.0 token (see the ver claim), the URI ends in /v2.0.',
    )
    idp: Optional[str] = Field(
        default=None,
        description='Records the identity provider that authenticated the subject of the token. This value is identical'
        ' to the value of the Issuer claim unless the user account is not in the same tenant as the issuer, such as'
        ' guests. Use the value of iss if the claim is not present.',
    )
    iat: int = Field(
        ...,
        description='Specifies when the authentication for this token occurred.',
    )
    nbf: int = Field(
        ...,
        description='Specifies the time after which the JWT can be processed.',
    )
    exp: int = Field(
        ...,
        description='Specifies the expiration time before which the JWT can be accepted for processing.',
    )
    aio: Optional[str] = Field(
        default=None,
        description='An internal claim used by Azure AD to record data for token reuse. Resources should not use this claim.',
    )
    name: Optional[str] = Field(
        default=None,
        description='Provides a human-readable value that identifies the subject of the token.',
    )
    scp: List[str] = Field(
        default=[],
        description='The set of scopes exposed by the application for which the client application has requested (and received) consent. Only included for user tokens.',
    )
    roles: List[str] = Field(
        default=[],
        description='The set of permissions exposed by the application that the requesting application or user has been given permission to call.',
    )
    wids: List[str] = Field(
        default=[],
        description='Denotes the tenant-wide roles assigned to this user, from the section of roles present in Azure AD built-in roles.',
    )
    groups: List[str] = Field(
        default=[],
        description='Provides object IDs that represent the group memberships of the subject.',
    )
    sub: str = Field(
        ...,
        description='The principal associated with the token.',
    )
    oid: str = Field(
        ...,
        description='The immutable identifier for the requestor, which is the verified identity of the user or service principal',
    )
    tid: str = Field(
        ...,
        description='Represents the tenant that the user is signing in to',
    )
    uti: Optional[str] = Field(
        default=None,
        description='Token identifier claim, equivalent to jti in the JWT specification. Unique, per-token identifier that is case-sensitive.',
    )
    rh: Optional[str] = Field(
        default=None,
        description='Token identifier claim, equivalent to jti in the JWT specification. Unique, per-token identifier that is case-sensitive.',
    )
    ver: Literal['1.0', '2.0'] = Field(
        ...,
        description='Indicates the version of the access token.',
    )

    # Optional claims, configured in Azure AD
    acct: Optional[str] = Field(
        default=None,
        description="User's account status in tenant",
    )
    auth_time: Optional[str] = Field(
        default=None,
        description='Time when the user last authenticated; See OpenID Connect spec',
    )
    ctry: Optional[str] = Field(
        default=None,
        description="User's country/region",
    )
    email: Optional[str] = Field(
        default=None,
        description='The addressable email for this user, if the user has one',
    )
    family_name: Optional[str] = Field(
        default=None,
        description='Provides the last name, surname, or family name of the user as defined in the user object',
    )
    fwd: Optional[str] = Field(
        default=None,
        description='IP address',
    )
    given_name: Optional[str] = Field(
        default=None,
        description='Provides the first or "given" name of the user, as set on the user object',
    )
    idtyp: Optional[str] = Field(
        default=None,
        description='Signals whether the token is an app-only token',
    )
    in_corp: Optional[str] = Field(
        default=None,
        description='Signals if the client is logging in from the corporate network; if they are not, the claim is not included',
    )
    ipaddr: Optional[str] = Field(
        default=None,
        description='The IP address the user authenticated from.',
    )
    login_hint: Optional[str] = Field(
        default=None,
        description='Login hint',
    )
    onprem_sid: Optional[str] = Field(
        default=None,
        description='On-premises security identifier',
    )
    pwd_exp: Optional[str] = Field(
        default=None,
        description='The datetime at which the password expires',
    )
    pwd_url: Optional[str] = Field(
        default=None,
        description='A URL that the user can visit to change their password',
    )
    sid: Optional[str] = Field(
        default=None,
        description='Session ID, used for per-session user sign out',
    )
    tenant_ctry: Optional[str] = Field(
        default=None,
        description="Resource tenant's country/region",
    )
    tenant_region_scope: Optional[str] = Field(
        default=None,
        description='Region of the resource tenant',
    )
    upn: Optional[str] = Field(
        default=None,
        description='An identifier for the user that can be used with the username_hint parameter; not a durable identifier for the user and should not be used to key data',
    )
    verified_primary_email: List[str] = Field(
        default=[],
        description="Sourced from the user's PrimaryAuthoritativeEmail",
    )
    verified_secondary_email: List[str] = Field(
        default=[],
        description="Sourced from the user's SecondaryAuthoritativeEmail",
    )
    vnet: Optional[str] = Field(
        default=None,
        description='VNET specifier information',
    )
    xms_pdl: Optional[str] = Field(
        default=None,
        description='Preferred data location',
    )
    xms_pl: Optional[str] = Field(
        default=None,
        description='User-preferred language',
    )
    xms_tpl: Optional[str] = Field(
        default=None,
        description='Tenant-preferred language',
    )
    ztdid: Optional[str] = Field(
        default=None,
        description='Zero-touch Deployment ID',
    )

    # V1.0 only
    acr: Optional[Literal['0', '1']] = Field(
        default=None,
        description='A value of 0 for the "Authentication context class" claim indicates the end-user authentication '
        'did not meet the requirements of ISO/IEC 29115. Only available in V1.0 tokens',
    )
    # V1.0 only
    amr: List[str] = Field(
        default=[],
        description='Identifies the authentication method of the subject of the token. Only available in V1.0 tokens',
    )
    # V1.0 only
    appid: Optional[str] = Field(
        default=None,
        description='The application ID of the client using the token. Only available in V1.0 tokens',
    )
    # V1.0 only
    appidacr: Optional[Literal['0', '1', '2']] = Field(
        default=None,
        description='Indicates authentication method of the client. Only available in V1.0 tokens',
    )
    # V1.0 only
    unique_name: Optional[str] = Field(
        default=None,
        description='Provides a human readable value that identifies the subject of the token. Only available in V1.0 tokens',
    )

    # V2.0 only
    azp: Optional[str] = Field(
        default=None,
        description='The application ID of the client using the token. Only available in V2.0 tokens',
    )
    # V2.0 only
    azpacr: Optional[Literal['0', '1', '2']] = Field(
        default=None,
        description='Indicates the authentication method of the client. Only available in V2.0 tokens',
    )
    # V2.0 only
    preferred_username: Optional[str] = Field(
        default=None,
        description='The primary username that represents the user. Only available in V2.0 tokens',
    )

    @validator('scp', pre=True)
    def scopes_to_list(cls, v: object) -> object:
        """
        Validator on the scope attribute that convert the space separated list
        of scope into an actual list of scope.
        """
        if isinstance(v, str):
            return v.split(' ')
        return v


class User(Claims):
    claims: Dict[str, Any] = Field(
        ...,
        description='The entire decoded token',
    )
    access_token: str = Field(
        ...,
        description='The access_token. Can be used for fetching the Graph API',
    )
    is_guest: bool = Field(
        False,
        description='The user is a guest user in the tenant',
    )
