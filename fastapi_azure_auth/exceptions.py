from fastapi import HTTPException, status


class InvalidAuth(HTTPException):
    """
    Exception raised when the user is not authorized
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={'WWW-Authenticate': 'Bearer'}
        )
