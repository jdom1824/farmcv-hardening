from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict, JsonValue
import json
import math
from typing import Annotated, Literal

Bytes32 = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{64}$")]


class StatusRequest(BaseModel):
    status: Literal["Active", "Suspended", "Revoked"]


class FarmCVRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    farm_id: Bytes32
    encrypted_cv: str = Field(min_length=1, max_length=100_000)
    encrypted_polygon: str = Field(min_length=1, max_length=100_000)
    cv_hash: Bytes32
    polygon_hash: Bytes32

    @field_validator("farm_id", "cv_hash", "polygon_hash")
    @classmethod
    def validate_bytes32_hex(cls, value: str) -> str:
        if not value.startswith("0x") or len(value) != 66:
            raise ValueError("must be a 32-byte hexadecimal value")
        int(value[2:], 16)
        if int(value[2:], 16) == 0:
            raise ValueError("must be nonzero")
        return value


class VerifyRequest(BaseModel):
    cv_hash: Bytes32
    polygon_hash: Bytes32


class FarmCVDocument(BaseModel):
    schema_version: str = "1.0"
    farm_id: str
    identification: dict[str, object]
    location: dict[str, object]
    production: dict[str, object] = {}
    quality: dict[str, object] = {}
    photos: list[dict[str, object]] = []
    documents: list[dict[str, object]] = []


class CVContent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    identification: dict[str, JsonValue] = Field(min_length=1)
    location: dict[str, JsonValue] = Field(min_length=1)
    production: dict[str, JsonValue] = Field(default_factory=dict)
    quality: dict[str, JsonValue] = Field(default_factory=dict)
    photos: list[dict[str, JsonValue]] = Field(default_factory=list, max_length=30)
    documents: list[dict[str, JsonValue]] = Field(default_factory=list, max_length=30)


class GeoPolygon(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["Polygon"]
    coordinates: list[list[tuple[float, float]]] = Field(min_length=1, max_length=20)

    @field_validator("coordinates")
    @classmethod
    def validate_rings(cls, rings):
        if sum(len(r) for r in rings) > 500:
            raise ValueError("polygon exceeds 500 points")
        for ring in rings:
            if len(ring) < 4 or ring[0] != ring[-1] or len(set(ring[:-1])) < 3:
                raise ValueError("rings must be closed with at least three distinct vertices")
            for lon, lat in ring:
                if not math.isfinite(lon) or not math.isfinite(lat) or not -180 <= lon <= 180 or not -90 <= lat <= 90:
                    raise ValueError("invalid longitude/latitude")
        return rings


class PlainFarmCVRequest(BaseModel):
    """Preferred admin input: no encryption key, ciphertext or hashes."""
    model_config = ConfigDict(extra="forbid")
    farm_id: Bytes32
    cv: CVContent
    polygon: GeoPolygon

    @model_validator(mode="after")
    def validate_document(self):
        if int(self.farm_id[2:], 16) == 0:
            raise ValueError("farm_id must be nonzero")
        encoded = json.dumps(self.model_dump(mode="json"), ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
        if len(encoded) > 16_384:
            raise ValueError("plaintext document exceeds 16 KiB")
        return self
