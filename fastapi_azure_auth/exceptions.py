from __future__ import annotations

from fastapi import HTTPException, WebSocketException, status
from starlette.requests import HTTPConnection


class InvalidAuthHttp(HTTPException):
    """
    Exception raised when the user is not authorized over HTTP
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={'WWW-Authenticate': 'Bearer'}
        )


class InvalidAuthWebSocket(WebSocketException):
    """
    Exception raised when the user is not authorized over WebSockets
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            code=status.WS_1008_POLICY_VIOLATION,
            reason=detail,
        )


def InvalidAuth(detail: str, request: HTTPConnection) -> InvalidAuthHttp | InvalidAuthWebSocket:
    """
    Returns the correct exception based on the connection type
    """
    if request.scope['type'] == 'http':
        return InvalidAuthHttp(detail)
    return InvalidAuthWebSocket(detail)
