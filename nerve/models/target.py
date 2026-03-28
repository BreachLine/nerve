"""Target models — discovered AI services and endpoints."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class AIServiceType(StrEnum):
    OLLAMA = "ollama"
    VLLM = "vllm"
    OPENAI_COMPAT = "openai_compatible"
    MCP_SERVER = "mcp_server"
    LITELLM = "litellm"
    LANGSERVE = "langserve"
    TRITON = "triton"
    TGI = "tgi"  # Text Generation Inference
    VECTOR_DB = "vector_db"
    CHATBOT = "chatbot"
    EMBEDDING = "embedding"
    UNKNOWN = "unknown"


class Endpoint(BaseModel):
    """A single discovered AI endpoint."""

    url: str
    service_type: AIServiceType = AIServiceType.UNKNOWN
    version: str = ""
    models: list[str] = Field(default_factory=list)
    auth_required: bool | None = None
    metadata: dict = Field(default_factory=dict)


class Target(BaseModel):
    """The full target specification for a Nerve scan."""

    # Primary target
    url: str = ""
    cidr: str = ""  # For network discovery

    # Auth for the target
    api_key: str = ""
    bearer_token: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    basic_auth: str = ""  # "user:pass"
    client_cert: str = ""
    client_key: str = ""

    # MCP-specific
    mcp_servers: list[MCPTarget] = Field(default_factory=list)

    # Vector DB-specific
    vector_dbs: list[VectorDBTarget] = Field(default_factory=list)

    # Chatbot-specific
    chatbots: list[ChatbotTarget] = Field(default_factory=list)

    # Discovered endpoints (populated by DiscoveryAgent)
    endpoints: list[Endpoint] = Field(default_factory=list)

    def get_auth_headers(self) -> dict[str, str]:
        """Build auth headers from configured credentials."""
        h = dict(self.headers)
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        return h


class MCPTarget(BaseModel):
    url: str = ""
    transport: str = "sse"  # "sse" or "stdio"
    command: str = ""  # For stdio transport
    token: str = ""
    env: dict[str, str] = Field(default_factory=dict)


class VectorDBTarget(BaseModel):
    db_type: str = "qdrant"  # qdrant, weaviate, milvus, pinecone
    url: str = ""
    api_key: str = ""
    collection: str = ""


class ChatbotTarget(BaseModel):
    url: str = ""
    chat_type: str = "rest"  # rest, websocket, openai
    session_endpoint: str = ""
    message_field: str = "content"
    response_field: str = "reply"
    headers: dict[str, str] = Field(default_factory=dict)
