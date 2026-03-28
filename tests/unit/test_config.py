"""Tests for Nerve configuration."""

from __future__ import annotations

import os
import tempfile

from nerve.config import NerveConfig


class TestConfig:
    def test_default_config(self):
        cfg = NerveConfig()
        assert cfg.llm.provider == "anthropic"
        assert cfg.llm.model == "claude-sonnet-4-5"
        assert cfg.scan.rate_limit == 10
        assert cfg.scan.timeout == 600

    def test_cli_overrides(self):
        cfg = NerveConfig.load(
            cli_overrides={
                "target": "http://test:11434",
                "llm_api_key": "test-dummy-key",
                "llm_provider": "openai",
                "rate_limit": 5,
                "format": "json,html,sarif",
                "fail_on": "high",
            }
        )
        assert cfg.target.url == "http://test:11434"
        assert cfg.llm.api_key == "test-dummy-key"
        assert cfg.llm.provider == "openai"
        assert cfg.scan.rate_limit == 5
        assert cfg.output.formats == ["json", "html", "sarif"]
        assert cfg.output.fail_on == "high"

    def test_cidr_detection(self):
        cfg = NerveConfig.load(cli_overrides={"target": "192.168.1.0/24"})
        assert cfg.target.cidr == "192.168.1.0/24"
        assert cfg.target.url == ""

    def test_yaml_loading(self):
        yaml_content = """
llm:
  provider: google
  model: gemini-2.5-flash
  api_key: test-key
scan:
  timeout: 300
  rate_limit: 5
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = NerveConfig.load(config_path=f.name)
        os.unlink(f.name)
        assert cfg.llm.provider == "google"
        assert cfg.llm.model == "gemini-2.5-flash"
        assert cfg.scan.timeout == 300

    def test_env_var_interpolation(self):
        os.environ["TEST_NERVE_KEY"] = "env-key-123"
        yaml_content = """
llm:
  api_key: ${TEST_NERVE_KEY}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = NerveConfig.load(config_path=f.name)
        os.unlink(f.name)
        os.environ.pop("TEST_NERVE_KEY", None)
        assert cfg.llm.api_key == "env-key-123"

    def test_target_auth_overrides(self):
        cfg = NerveConfig.load(
            cli_overrides={
                "target": "http://test",
                "target_api_key": "target-key",
                "target_headers": "X-Auth:token123,X-Org:myorg",
            }
        )
        assert cfg.target.api_key == "target-key"
        assert cfg.target.headers["X-Auth"] == "token123"
        assert cfg.target.headers["X-Org"] == "myorg"

    def test_mcp_override(self):
        cfg = NerveConfig.load(
            cli_overrides={
                "target": "http://mcp:3000",
                "mcp_token": "mcp-secret",
            }
        )
        assert len(cfg.target.mcp_servers) == 1
        assert cfg.target.mcp_servers[0].token == "mcp-secret"

    def test_vector_db_override(self):
        cfg = NerveConfig.load(
            cli_overrides={
                "target": "http://app",
                "qdrant_url": "http://qdrant:6333",
                "qdrant_api_key": "qd-key",
            }
        )
        assert len(cfg.target.vector_dbs) == 1
        assert cfg.target.vector_dbs[0].db_type == "qdrant"
        assert cfg.target.vector_dbs[0].api_key == "qd-key"
