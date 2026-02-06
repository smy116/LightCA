from typing import Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field, model_validator


class TemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    template_type: Optional[str] = Field(None, max_length=64)
    type: Optional[str] = Field(None, max_length=64)
    description: Optional[str] = None
    subject_dn: Optional[str] = None
    validity_days: Optional[int] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    key_curve: Optional[str] = None
    is_ca: Optional[bool] = None
    basic_constraints_ca: Optional[bool] = None
    basic_constraints_path_length: Optional[int] = None
    key_usage: Dict[str, Any] = Field(default_factory=dict)
    extended_key_usage: Dict[str, Any] = Field(default_factory=dict)
    policy: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize(self):
        if not self.template_type:
            self.template_type = self.type or "leaf"

        if self.description and "description" not in self.policy:
            self.policy["description"] = self.description
        if self.subject_dn and "subject_dn" not in self.policy:
            self.policy["subject_dn"] = self.subject_dn
        if self.validity_days and "validity_days" not in self.policy:
            self.policy["validity_days"] = self.validity_days
        if self.key_algorithm and "key_algorithm" not in self.policy:
            self.policy["key_algorithm"] = self.key_algorithm
        if self.key_size and "key_size" not in self.policy:
            self.policy["key_size"] = self.key_size
        if self.key_curve and "key_curve" not in self.policy:
            self.policy["key_curve"] = self.key_curve
        if self.basic_constraints_ca is not None:
            self.policy["basic_constraints_ca"] = self.basic_constraints_ca
        if self.basic_constraints_path_length is not None:
            self.policy["basic_constraints_path_length"] = self.basic_constraints_path_length

        return self


class TemplateUpdateRequest(BaseModel):
    template_id: int
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    template_type: Optional[str] = Field(None, max_length=64)
    type: Optional[str] = Field(None, max_length=64)
    description: Optional[str] = None
    validity_days: Optional[int] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    key_curve: Optional[str] = None
    key_usage: Optional[Dict[str, Any]] = None
    extended_key_usage: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def normalize(self):
        if not self.template_type and self.type:
            self.template_type = self.type

        if self.policy is None:
            self.policy = {}
        if self.description is not None:
            self.policy["description"] = self.description
        if self.validity_days is not None:
            self.policy["validity_days"] = self.validity_days
        if self.key_algorithm is not None:
            self.policy["key_algorithm"] = self.key_algorithm
        if self.key_size is not None:
            self.policy["key_size"] = self.key_size
        if self.key_curve is not None:
            self.policy["key_curve"] = self.key_curve

        return self


class TemplateDetail(BaseModel):
    id: int
    name: str
    template_type: str
    key_usage: Dict[str, Any]
    extended_key_usage: Dict[str, Any]
    policy: Dict[str, Any]
    is_builtin: bool
    created_at: datetime
    updated_at: datetime


class TemplateListResponse(BaseModel):
    templates: list[TemplateDetail]
    total: int
    page: int
    per_page: int


class TemplateDeleteRequest(BaseModel):
    template_id: int
