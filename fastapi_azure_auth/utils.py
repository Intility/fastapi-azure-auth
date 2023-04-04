from typing import Any, Dict


def is_guest(claims: Dict[str, Any]) -> bool:
    """
    Check if the user is a guest user
    """
    # if the user has set up `acct` claim in Azure, that's most efficient. 0 = tenant member, 1 = guest
    if claims.get('acct') == 1:
        return True
    # formula: idp exist and idp != iss: guest user
    claims_iss: str = claims.get('iss', '')
    idp: str = claims.get('idp', claims_iss)
    return idp != claims_iss
