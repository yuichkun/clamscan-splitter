"""Tests for configuration loading."""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from clamscan_splitter.config import ConfigLoader, load_config


class TestConfigLoader:
    """Test ConfigLoader class."""

    def test_load_yaml_config(self, tmp_path):
        """Test loading YAML configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "chunking": {
                "target_size_gb": 20.0,
                "max_files_per_chunk": 50000,
            },
            "scanning": {
                "max_concurrent_processes": 8,
                "base_timeout_per_gb": 30,
            },
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        loader = ConfigLoader()
        config = loader.load_config(str(config_file))
        
        assert config["chunking"]["target_size_gb"] == 20.0
        assert config["scanning"]["max_concurrent_processes"] == 8

    def test_load_json_config(self, tmp_path):
        """Test loading JSON configuration."""
        config_file = tmp_path / "config.json"
        config_data = {
            "chunking": {
                "target_size_gb": 15.0,
                "max_files_per_chunk": 30000,
            },
            "scanning": {
                "max_concurrent_processes": 4,
            },
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        loader = ConfigLoader()
        config = loader.load_config(str(config_file))
        
        assert config["chunking"]["target_size_gb"] == 15.0

    def test_load_default_config(self):
        """Test loading default configuration."""
        loader = ConfigLoader()
        config = loader.load_default_config()
        
        assert "chunking" in config
        assert "scanning" in config
        assert config["chunking"]["target_size_gb"] > 0

    def test_merge_configs(self):
        """Test merging multiple configurations."""
        loader = ConfigLoader()
        
        base = {
            "chunking": {"target_size_gb": 15.0},
            "scanning": {"max_concurrent_processes": 4},
        }
        
        override = {
            "chunking": {"target_size_gb": 20.0},
        }
        
        merged = loader.merge_configs(base, override)
        
        assert merged["chunking"]["target_size_gb"] == 20.0
        assert merged["scanning"]["max_concurrent_processes"] == 4

    def test_validate_config(self):
        """Test configuration validation."""
        loader = ConfigLoader()
        
        # Valid config
        valid_config = {
            "chunking": {"target_size_gb": 15.0, "max_files_per_chunk": 30000},
            "scanning": {"max_concurrent_processes": 4},
        }
        
        assert loader.validate_config(valid_config) is True
        
        # Invalid config (negative value)
        invalid_config = {
            "chunking": {"target_size_gb": -5.0},
        }
        
        assert loader.validate_config(invalid_config) is False


def test_load_config_function(tmp_path):
    """Test load_config convenience function."""
    config_file = tmp_path / "config.yaml"
    config_data = {
        "chunking": {"target_size_gb": 20.0},
    }
    
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)
    
    config = load_config(str(config_file))
    
    assert config["chunking"]["target_size_gb"] == 20.0

