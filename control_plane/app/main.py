"""Customer-facing API only. There is no admin web panel; the operator uses the `novavpn-admin` command."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import core

app = FastAPI(title="NovaVPN Private API", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)


class LoginInput(BaseModel):
    username: str = Field(min_length=3, max_length=190)
    password: str = Field(min_length=1, max_length=256)


class PasswordInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@app.on_event("startup")
def startup() -> None:
    core.init_db()


def current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Sign-in required.")
    try:
        return core.user_from_token(authorization.split(" ", 1)[1].strip())
    except core.CoreError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "novavpn-api", "time": core.utc_now()}


@app.post("/api/v1/auth/login")
def login(payload: LoginInput) -> dict[str, Any]:
    try:
        return core.authenticate(payload.username, payload.password)
    except core.CoreError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc


@app.get("/api/v1/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"username": user["username"], "email": user["email"], "role": "user",
            "must_change_password": bool(user["must_change_password"])}


@app.post("/api/v1/auth/change-password")
def change_password(payload: PasswordInput, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    try:
        core.change_password(user["id"], payload.current_password, payload.new_password)
    except core.CoreError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc
    return {"status": "password_updated"}


@app.get("/api/v1/locations")
def locations(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"locations": core.list_locations(user["id"])}


@app.get("/api/v1/profiles/{location_code}/config")
def profile(location_code: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    try:
        return core.get_profile(user["id"], location_code)
    except core.CoreError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc


@app.exception_handler(Exception)
async def unexpected_error(_: Request, exc: Exception):
    print(f"NovaVPN internal error: {type(exc).__name__}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})
