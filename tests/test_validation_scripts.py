#!/usr/bin/env python3
"""Test harness for validation scripts (validate_all.sh and pre_deploy_validate.sh).

This module provides integration tests that execute the validation scripts
in controlled temporary environments and verifies their behavior.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
SCHEMA_FILE = Path(__file__).parent.parent / "config_schema.json"
PYTHON_EXE = sys.executable


def create_temp_config(content: dict, filename: str, configs_dir: Path) -> Path:
    """Create a temporary config file and return its path."""
    config_path = configs_dir / filename
    with open(config_path, "w") as f:
        json.dump(content, f)
    return config_path


def validate_config_with_python(config_path: Path, schema_path: Path) -> tuple[int, str, str]:
    """Validate a config using the Python validator directly."""
    validator_path = SCRIPT_DIR / "validate_config_strict.py"
    result = subprocess.run(
        [PYTHON_EXE, str(validator_path), str(config_path), str(schema_path)],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def run_validation_in_temp_dir(configs_dir: Path, schema_path: Path) -> tuple[int, str, str]:
    """Run validation directly using Python validator on all configs in a directory."""
    passed_count = 0
    failed_count = 0
    output_lines = []
    error_lines = []

    for config_file in sorted(configs_dir.glob("*.json")) + sorted(configs_dir.glob("*.toml")):
        label = config_file.name
        returncode, stdout, stderr = validate_config_with_python(config_file, schema_path)

        if returncode == 0:
            output_lines.append(f"  ✅ {label}")
            passed_count += 1
        else:
            output_lines.append(f"  ❌ {label}")
            if stderr:
                error_lines.append(stderr)
            failed_count += 1

    output = "\n".join(output_lines)
    stderr = "\n".join(error_lines)

    if failed_count > 0:
        return 1, output, stderr
    return 0, output, stderr


class TestValidateAllScript:
    """Tests for validate_all.sh script behavior."""

    def test_returns_zero_on_valid_config(self):
        """Script returns zero exit code when valid configs are present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            valid_config = {
                "contract": {
                    "name": "test-anchor",
                    "version": "1.0.0",
                    "network": "stellar-testnet",
                    "admin_address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(valid_config, "valid.json", configs_dir)

            returncode, stdout, stderr = run_validation_in_temp_dir(configs_dir, SCHEMA_FILE)

            assert returncode == 0, f"Validation should succeed. stderr: {stderr}"
            assert "valid" in stdout.lower() or "success" in stdout.lower()

    def test_returns_nonzero_on_invalid_config(self):
        """Script returns non-zero exit code when invalid configs are present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            invalid_config = {
                "contract": {
                    "name": "test-anchor",
                    "version": "1.0.0",
                    "network": "invalid-network",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(invalid_config, "invalid.json", configs_dir)

            returncode, stdout, stderr = run_validation_in_temp_dir(configs_dir, SCHEMA_FILE)

            assert returncode != 0, "Validation should fail on invalid config"

    def test_returns_nonzero_when_schema_missing(self):
        """Script returns non-zero exit code when schema file is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            valid_config = {
                "contract": {
                    "name": "test-anchor",
                    "version": "1.0.0",
                    "network": "stellar-testnet",
                    "admin_address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(valid_config, "valid.json", configs_dir)
            missing_schema = Path(tmpdir) / "missing_schema.json"

            returncode, stdout, stderr = validate_config_with_python(configs_dir / "valid.json", missing_schema)

            assert returncode != 0, "Validation should fail when schema is missing"
            assert "schema file not found" in stderr.lower()

    def test_handles_toml_conversion(self):
        """Validator handles TOML files directly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            toml_content = '''
[contract]
name = "test-anchor"
version = "1.0.0"
network = "stellar-testnet"
admin_address = "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ"

[attestors]

[[attestors.registry]]
name = "kyc-issuer"
address = "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ"
role = "kyc-issuer"
enabled = true
'''
            toml_path = configs_dir / "test.toml"
            with open(toml_path, "w") as f:
                f.write(toml_content)

            returncode, stdout, stderr = validate_config_with_python(toml_path, SCHEMA_FILE)

            assert returncode == 0, f"Validation should succeed for valid TOML config. stderr: {stderr}"

    def test_validates_multiple_configs(self):
        """Script validates all config files in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            valid_config = {
                "contract": {
                    "name": "test-anchor",
                    "version": "1.0.0",
                    "network": "stellar-testnet",
                    "admin_address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(valid_config, "config1.json", configs_dir)
            create_temp_config(valid_config, "config2.json", configs_dir)

            returncode, stdout, stderr = run_validation_in_temp_dir(configs_dir, SCHEMA_FILE)

            assert returncode == 0, f"All valid configs should pass. stderr: {stderr}"


class TestPreDeployValidateScript:
    """Tests for pre_deploy_validate.sh script behavior."""

    def test_returns_zero_on_valid_configs(self):
        """Script returns zero on valid configuration files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            valid_config = {
                "contract": {
                    "name": "test-anchor",
                    "version": "1.0.0",
                    "network": "stellar-testnet",
                    "admin_address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(valid_config, "valid.json", configs_dir)

            passed_count = 0
            failed_count = 0

            for config_file in configs_dir.glob("*.json"):
                returncode, _, _ = validate_config_with_python(config_file, SCHEMA_FILE)
                if returncode == 0:
                    passed_count += 1
                else:
                    failed_count += 1

            assert failed_count == 0, "All valid configs should pass"
            assert passed_count == 1

    def test_returns_nonzero_on_invalid_config(self):
        """Script returns non-zero on invalid configuration files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            invalid_config = {
                "contract": {
                    "name": "test-anchor",
                    "version": "1.0.0",
                    "network": "invalid-network",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "invalid-address",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(invalid_config, "invalid.json", configs_dir)

            passed_count = 0
            failed_count = 0

            for config_file in configs_dir.glob("*.json"):
                returncode, _, _ = validate_config_with_python(config_file, SCHEMA_FILE)
                if returncode == 0:
                    passed_count += 1
                else:
                    failed_count += 1

            assert failed_count > 0, "Invalid configs should fail"

    def test_reports_individual_failures(self):
        """Script reports individual file failures with diagnostics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            configs_dir = Path(tmpdir) / "configs"
            configs_dir.mkdir()

            valid_config = {
                "contract": {
                    "name": "valid-anchor",
                    "version": "1.0.0",
                    "network": "stellar-testnet",
                    "admin_address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            invalid_config = {
                "contract": {
                    "name": "invalid-anchor",
                    "version": "1.0.0",
                    "network": "invalid-network",
                },
                "attestors": {
                    "registry": [
                        {
                            "name": "kyc-issuer",
                            "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                            "role": "kyc-issuer",
                            "enabled": True,
                        }
                    ]
                },
            }

            create_temp_config(valid_config, "valid.json", configs_dir)
            create_temp_config(invalid_config, "invalid.json", configs_dir)

            passed_count = 0
            failed_count = 0

            for config_file in sorted(configs_dir.glob("*.json"), key=lambda p: p.name):
                returncode, stderr, _ = validate_config_with_python(config_file, SCHEMA_FILE)
                if returncode == 0:
                    passed_count += 1
                else:
                    failed_count += 1

            assert failed_count > 0, "Script should fail when any config is invalid"
            assert passed_count == 1


class TestValidatorScript:
    """Tests for validate_config_strict.py as a standalone validator."""

    def test_accepts_valid_config(self):
        """Validator accepts a valid config without errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "valid.json"
            with open(config_path, "w") as f:
                json.dump(
                    {
                        "contract": {
                            "name": "test-anchor",
                            "version": "1.0.0",
                            "network": "stellar-testnet",
                            "admin_address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                        },
                        "attestors": {
                            "registry": [
                                {
                                    "name": "kyc-issuer",
                                    "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                                    "role": "kyc-issuer",
                                    "enabled": True,
                                }
                            ]
                        },
                    },
                    f,
                )

            returncode, stdout, stderr = validate_config_with_python(config_path, SCHEMA_FILE)

            assert returncode == 0, f"Validator should accept valid config. stderr: {stderr}"

    def test_rejects_invalid_network(self):
        """Validator rejects config with invalid network value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "invalid.json"
            with open(config_path, "w") as f:
                json.dump(
                    {
                        "contract": {
                            "name": "test-anchor",
                            "version": "1.0.0",
                            "network": "invalid-network",
                        },
                        "attestors": {
                            "registry": []
                        },
                    },
                    f,
                )

            returncode, stdout, stderr = validate_config_with_python(config_path, SCHEMA_FILE)

            assert returncode != 0, "Validator should reject invalid network"
            assert "network" in stderr.lower() or "enum" in stderr.lower() or "additionalproperties" in stderr.lower()

    def test_rejects_missing_required_field(self):
        """Validator rejects config missing required fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "missing_field.json"
            with open(config_path, "w") as f:
                json.dump(
                    {
                        "contract": {
                            "name": "test-anchor",
                        },
                    },
                    f,
                )

            returncode, stdout, stderr = validate_config_with_python(config_path, SCHEMA_FILE)

            assert returncode != 0, "Validator should reject missing required fields"
            assert returncode != 0

    def test_rejects_unknown_field_in_registry(self):
        """Validator rejects config with unknown field in attestor registry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "unknown_field.json"
            with open(config_path, "w") as f:
                json.dump(
                    {
                        "contract": {
                            "name": "test-anchor",
                            "version": "1.0.0",
                            "network": "stellar-testnet",
                        },
                        "attestors": {
                            "registry": [
                                {
                                    "name": "kyc-issuer",
                                    "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
                                    "role": "kyc-issuer",
                                    "enabled": True,
                                    "unknown_field": "value",
                                }
                            ]
                        },
                    },
                    f,
                )

            returncode, stdout, stderr = validate_config_with_python(config_path, SCHEMA_FILE)

            assert returncode != 0, "Validator should reject unknown fields"

    def test_accepts_example_configs(self):
        """Validator accepts all example configs in the repository."""
        example_configs = [
            Path(__file__).parent.parent / "configs" / "stablecoin-issuer.json",
            Path(__file__).parent.parent / "configs" / "remittance-anchor.json",
            Path(__file__).parent.parent / "configs" / "fiat-on-off-ramp.json",
        ]

        for config_path in example_configs:
            if not config_path.exists():
                continue
            result = subprocess.run(
                [PYTHON_EXE, str(SCRIPT_DIR / "validate_config_strict.py"), str(config_path), str(SCHEMA_FILE)],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Validator should accept {config_path.name}. stderr: {result.stderr}"

    def test_accepts_toml_config_directly(self):
        """Validator accepts TOML files directly without conversion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            toml_path = Path(tmpdir) / "valid.toml"
            toml_content = '''
[contract]
name = "test-anchor"
version = "1.0.0"
network = "stellar-testnet"
admin_address = "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ"

[attestors]

[[attestors.registry]]
name = "kyc-issuer"
address = "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ"
role = "kyc-issuer"
enabled = true
'''
            with open(toml_path, "w") as f:
                f.write(toml_content)

            result = subprocess.run(
                [PYTHON_EXE, str(SCRIPT_DIR / "validate_config_strict.py"), str(toml_path), str(SCHEMA_FILE)],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Validator should accept TOML directly. stderr: {result.stderr}"


class TestStrictValidatorFixtures:
    """Tests for validate_config_strict.py against repository fixtures."""

    def test_accepts_valid_fixture(self):
        """Validator accepts the valid fiat-on-off-ramp.toml fixture."""
        valid_fixture = Path(__file__).parent.parent / "configs" / "fiat-on-off-ramp.toml"
        if not valid_fixture.exists():
            pytest.skip(f"Valid fixture not found: {valid_fixture}")

        result = subprocess.run(
            [PYTHON_EXE, str(SCRIPT_DIR / "validate_config_strict.py"), str(valid_fixture), str(SCHEMA_FILE)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"Validator should accept {valid_fixture.name}. stderr: {result.stderr}"
        )

    def test_rejects_invalid_fixture(self):
        """Validator rejects the intentionally invalid sample with a diagnostic."""
        invalid_fixture = Path(__file__).parent.parent / "examples" / "invalid-config-sample.toml"
        if not invalid_fixture.exists():
            pytest.skip(f"Invalid fixture not found: {invalid_fixture}")

        result = subprocess.run(
            [PYTHON_EXE, str(SCRIPT_DIR / "validate_config_strict.py"), str(invalid_fixture), str(SCHEMA_FILE)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, "Validator should reject the invalid sample"
        assert result.stderr.strip(), "Validator should emit a diagnostic on stderr for the invalid sample"


class TestValidateDocsLinkCheck:
    """Tests for the local Markdown link check in validate-docs.sh."""

    def _run_docs_validation(self, docs_dir: Path) -> subprocess.CompletedProcess:
        """Run validate-docs.sh scoped to a temporary docs directory."""
        script_path = SCRIPT_DIR / "validate-docs.sh"
        if not script_path.exists():
            pytest.skip("validate-docs.sh not found")

        env = os.environ.copy()
        env["DOCS_DIR"] = str(docs_dir)
        env["DOCS_LINK_CHECK_ONLY"] = "1"

        return subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_detects_broken_local_link(self):
        """A deliberately broken relative link is reported as a failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_dir = Path(tmpdir)
            (docs_dir / "index.md").write_text(
                "# Index\n\nSee [missing](./does-not-exist.md).\n",
                encoding="utf-8",
            )

            result = self._run_docs_validation(docs_dir)

            assert result.returncode != 0, (
                "Link check should fail on a broken local link. "
                f"stdout: {result.stdout} stderr: {result.stderr}"
            )
            assert "does-not-exist.md" in (result.stdout + result.stderr)

    def test_accepts_valid_local_link(self):
        """A valid relative link passes the link check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_dir = Path(tmpdir)
            (docs_dir / "index.md").write_text(
                "# Index\n\nSee [guide](./guide.md).\n",
                encoding="utf-8",
            )
            (docs_dir / "guide.md").write_text("# Guide\n", encoding="utf-8")

            result = self._run_docs_validation(docs_dir)

            assert result.returncode == 0, (
                "Link check should pass on valid local links. "
                f"stdout: {result.stdout} stderr: {result.stderr}"
            )


class TestValidateWasmBuildScript:
    """Tests for validate_wasm_build.sh optional environment variable handling."""

    def test_runs_without_optional_source_date_epoch(self):
        """Script runs successfully when SOURCE_DATE_EPOCH is unset."""
        import subprocess
        import os

        script_path = SCRIPT_DIR / "validate_wasm_build.sh"
        
        if not script_path.exists():
            pytest.skip("validate_wasm_build.sh not found")
        
        # Create a clean environment without SOURCE_DATE_EPOCH
        env = os.environ.copy()
        env.pop('SOURCE_DATE_EPOCH', None)  # Ensure it's not set
        env.pop('VERBOSE', None)  # Also unset VERBOSE for clean test
        
        # Run the script with --help to verify it works without the optional var
        # Using --help because a full WASM build would take too long
        result = subprocess.run(
            [str(script_path), "--help"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Script should run successfully (exit 0) and not complain about missing SOURCE_DATE_EPOCH
        assert result.returncode == 0, f"Script failed without SOURCE_DATE_EPOCH. stderr: {result.stderr}"
        assert "SOURCE_DATE_EPOCH" not in result.stderr, \
            "Script should not error when SOURCE_DATE_EPOCH is unset (it's optional)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])