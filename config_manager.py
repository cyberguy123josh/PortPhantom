"""
PortPhantom Configuration Manager
Handles persistent settings and scan profiles
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any


class ConfigManager:
    """Manages application settings persistence"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.settings_file = self.config_dir / "settings.json"
        self._ensure_config_dir()
        self.settings = self._load_settings()
    
    def _ensure_config_dir(self):
        """Create config directory if it doesn't exist"""
        self.config_dir.mkdir(exist_ok=True)
    
    def _get_default_settings(self) -> Dict[str, Any]:
        """Return default settings"""
        return {
            "theme": "dark",
            "window": {
                "width": 1400,
                "height": 900,
                "x": 50,
                "y": 50
            },
            "last_scan": {
                "target": "",
                "port_mode": "common",
                "scan_type": "connect",
                "threads": 10,
                "service_detection": True
            },
            "preferences": {
                "auto_save": True,
                "show_notifications": True,
                "notification_sound": False,
                "auto_open_details": True,
                "remember_filters": True
            },
            "recent_targets": [],
            "max_recent_targets": 10,
            "last_filter": {
                "search": "",
                "state": "all"
            }
        }
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from JSON file"""
        if not self.settings_file.exists():
            return self._get_default_settings()
        
        try:
            with open(self.settings_file, 'r') as f:
                loaded = json.load(f)
                defaults = self._get_default_settings()
                return self._merge_dicts(defaults, loaded)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load settings ({e}), using defaults")
            return self._get_default_settings()
    
    def _merge_dicts(self, default: Dict, loaded: Dict) -> Dict:
        """Recursively merge loaded settings with defaults"""
        result = default.copy()
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_dicts(result[key], value)
            else:
                result[key] = value
        return result
    
    def save(self):
        """Save current settings to JSON file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except IOError as e:
            print(f"Error saving settings: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.settings
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set a setting value by key (supports dot notation)"""
        keys = key.split('.')
        target = self.settings
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value
    
    def add_recent_target(self, target: str):
        """Add a target to recent targets list"""
        recent = self.settings.get("recent_targets", [])
        if target in recent:
            recent.remove(target)
        recent.insert(0, target)
        max_recent = self.settings.get("max_recent_targets", 10)
        self.settings["recent_targets"] = recent[:max_recent]
    
    def get_recent_targets(self) -> List[str]:
        """Get list of recent targets"""
        return self.settings.get("recent_targets", [])


class ProfileManager:
    """Manages scan profiles"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.profiles_file = self.config_dir / "profiles.json"
        self._ensure_config_dir()
        self.profiles = self._load_profiles()
    
    def _ensure_config_dir(self):
        """Create config directory if it doesn't exist"""
        self.config_dir.mkdir(exist_ok=True)
    
    def _get_default_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Return default scan profiles"""
        return {
            "Quick Scan": {
                "description": "Fast scan of common ports",
                "port_mode": "common",
                "scan_type": "connect",
                "threads": 50,
                "service_detection": False,
                "os_detection": False,
                "vuln_scan": False
            },
            "Full Scan": {
                "description": "Comprehensive scan with all features",
                "port_mode": "all",
                "scan_type": "connect",
                "threads": 20,
                "service_detection": True,
                "os_detection": True,
                "vuln_scan": True
            },
            "Stealth Scan": {
                "description": "SYN scan with service detection",
                "port_mode": "common",
                "scan_type": "syn",
                "threads": 10,
                "service_detection": True,
                "os_detection": False,
                "vuln_scan": False
            },
            "Web Services": {
                "description": "Scan common web ports",
                "port_mode": "web",
                "scan_type": "connect",
                "threads": 30,
                "service_detection": True,
                "os_detection": False,
                "vuln_scan": True
            }
        }
    
    def _load_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Load profiles from JSON file"""
        if not self.profiles_file.exists():
            profiles = self._get_default_profiles()
            self._save_profiles(profiles)
            return profiles
        
        try:
            with open(self.profiles_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load profiles ({e}), using defaults")
            return self._get_default_profiles()
    
    def _save_profiles(self, profiles: Dict[str, Dict[str, Any]]):
        """Save profiles to JSON file"""
        try:
            with open(self.profiles_file, 'w') as f:
                json.dump(profiles, f, indent=2)
            return True
        except IOError as e:
            print(f"Error saving profiles: {e}")
            return False
    
    def list_profiles(self) -> List[str]:
        """Get list of profile names"""
        return list(self.profiles.keys())
    
    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Get profile by name"""
        return self.profiles.get(name)
    
    def create_profile(self, name: str, config: Dict[str, Any]) -> bool:
        """Create a new profile"""
        if name in self.profiles:
            return False
        self.profiles[name] = config
        return self._save_profiles(self.profiles)
    
    def update_profile(self, name: str, config: Dict[str, Any]) -> bool:
        """Update an existing profile"""
        if name not in self.profiles:
            return False
        self.profiles[name] = config
        return self._save_profiles(self.profiles)
    
    def delete_profile(self, name: str) -> bool:
        """Delete a profile"""
        if name not in self.profiles:
            return False
        del self.profiles[name]
        return self._save_profiles(self.profiles)
    
    def save(self) -> bool:
        """Save current profiles to disk"""
        return self._save_profiles(self.profiles)
