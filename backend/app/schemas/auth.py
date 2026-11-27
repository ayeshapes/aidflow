from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    # Upper bounds stop someone sending a megabyte "password" to waste CPU.
    # No password POLICY here: login must accept whatever was stored, and
    # policy messages would reveal the rules to attackers.
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256, repr=False)  # repr=False keeps it out of debug output

    model_config = ConfigDict(extra="forbid")


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class MessageOut(BaseModel):
    message: str
