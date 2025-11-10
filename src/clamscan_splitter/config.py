"""Configuration loading module."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class ConfigLoader:
    """Loads and validates configuration from files."""

    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file or return defaults.

        Args:
            config_path: Path to config file (YAML or JSON)

        Returns:
            Configuration dictionary
        """
        if config_path and Path(config_path).exists():
            return self._load_from_file(config_path)
        return self.load_default_config()

    def _load_from_file(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file."""
        path = Path(config_path)
        
        if path.suffix in ['.yaml', '.yml']:
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        elif path.suffix == '.json':
            with open(path, 'r') as f:
                return json.load(f)
        else:
            raise ValueError(f"Unsupported config file format: {path.suffix}")

    def load_default_config(self) -> Dict[str, Any]:
        """
        Load default configuration.

        Returns:
            Default configuration dictionary
        """
        return {
            "chunking": {
                "target_size_gb": 15.0,
                "max_files_per_chunk": 30000,
                "isolate_large_files_gb": 1.0,
            },
            "scanning": {
                "max_concurrent_processes": None,  # Auto-calculate
                "base_timeout_per_gb": 30,
                "min_timeout_seconds": 300,
                "max_timeout_seconds": 3600,
                "memory_per_process_gb": 2.0,
                "min_free_memory_gb": 2.0,
            },
            "retry": {
                "max_attempts": 3,
                "max_attempts_per_file": 2,
                "base_delay_seconds": 1.0,
                "max_delay_seconds": 300.0,
                "exponential_base": 2.0,
            },
        }

    def merge_configs(
        self, base: Dict[str, Any], override: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Merge two configuration dictionaries.

        Args:
            base: Base configuration
            override: Override configuration

        Returns:
            Merged configuration
        """
        merged = base.copy()
        
        for key, value in override.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self.merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration values.

        Args:
            config: Configuration to validate

        Returns:
            True if valid, False otherwise
        """
        # Validate chunking config
        if "chunking" in config:
            chunking = config["chunking"]
            if "target_size_gb" in chunking:
                if chunking["target_size_gb"] <= 0:
                    return False
            if "max_files_per_chunk" in chunking:
                if chunking["max_files_per_chunk"] <= 0:
                    return False
        
        # Validate scanning config
        if "scanning" in config:
            scanning = config["scanning"]
            if "base_timeout_per_gb" in scanning:
                if scanning["base_timeout_per_gb"] <= 0:
                    return False
            if "memory_per_process_gb" in scanning:
                if scanning["memory_per_process_gb"] <= 0:
                    return False
        
        return True


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to load configuration.

    Args:
        config_path: Path to config file

    Returns:
        Configuration dictionary
    """
    loader = ConfigLoader()
    return loader.load_config(config_path)

