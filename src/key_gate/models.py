from __future__ import annotations

from pydantic import BaseModel, Field


class IssueRequest(BaseModel):
    """Contrato de entrada de `POST /keys`: para quién, con qué permisos y hasta cuándo."""

    client: str = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)
    ttl_seconds: float | None = Field(default=None, gt=0)


class Watch(BaseModel):
    """Una señal que merece mirarse: cita una clave o un cliente que está en el registro."""

    senal: str = Field(min_length=1)
    motivo: str = Field(min_length=1)
    accion: str = Field(min_length=1)


class AccessDigest(BaseModel):
    """El registro de accesos, narrado (`access-digest-v1`)."""

    summary: str = Field(min_length=1)
    watch: list[Watch] = Field(default_factory=list)
