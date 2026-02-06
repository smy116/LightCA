from pydantic import BaseModel


class StatsResponse(BaseModel):
    ca_count: int
    cert_count: int
    expiring_count: int
    revoked_count: int
