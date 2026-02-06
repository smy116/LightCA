from typing import Any, Dict, Optional
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    code: str
    detail: str


class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error: Optional[ErrorDetail] = None


def create_response(
    success: bool,
    message: str,
    data: Optional[Any] = None,
    error_code: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> ApiResponse:
    error = None
    if error_code and error_detail:
        error = ErrorDetail(code=error_code, detail=error_detail)
    
    return ApiResponse(
        success=success,
        message=message,
        data=data,
        error=error,
    )


def success_response(message: str = "Success", data: Optional[Any] = None) -> ApiResponse:
    return create_response(success=True, message=message, data=data)


def error_response(message: str = "Error", error_code: str = "ERROR", error_detail: Optional[str] = None) -> ApiResponse:
    return create_response(
        success=False,
        message=message,
        error_code=error_code,
        error_detail=error_detail or message,
    )
