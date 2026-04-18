#!/usr/bin/env python3
"""
MiniMax OAuth Token Storage

Handles persistent storage of OAuth tokens and session data.
Follows the same patterns as mcp_oauth_manager.py for consistency.
"""

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import time

logger = logging.getLogger(__name__)

@dataclass
class StoredTokenData:
    """Stored OAuth token data."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_at: Optional[float] = None
    scope: Optional[str] = None
    region: str = "global"

class MiniMaxOAuthStorage:
    """Persistent storage for MiniMax OAuth tokens."""
    
    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or Path.home() / ".hermes" / "minimax_oauth"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.tokens_file = self.storage_dir / "tokens.json"
        self._lock = threading.Lock()
        self._cache: Dict[str, StoredTokenData] = {}
        self._load_tokens()
    
    def _load_tokens(self) -> None:
        """Load tokens from disk."""
        try:
            if self.tokens_file.exists():
                with open(self.tokens_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for region, token_data in data.items():
                        self._cache[region] = StoredTokenData(**token_data)
                logger.info(f"Loaded {len(self._cache)} tokens from storage")
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning(f"Failed to load tokens from {self.tokens_file}: {e}")
            self._cache = {}
    
    def _save_tokens(self) -> None:
        """Save tokens to disk."""
        try:
            data = {}
            for region, token_data in self._cache.items():
                data[region] = {
                    "access_token": token_data.access_token,
                    "refresh_token": token_data.refresh_token,
                    "token_type": token_data.token_type,
                    "expires_at": token_data.expires_at,
                    "scope": token_data.scope,
                    "region": token_data.region
                }
            
            # Write to temporary file first, then rename for atomicity
            temp_file = self.tokens_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            temp_file.replace(self.tokens_file)
            
            logger.info(f"Saved {len(self._cache)} tokens to storage")
        except OSError as e:
            logger.error(f"Failed to save tokens to {self.tokens_file}: {e}")
    
    def store_token(self, token_data: Dict[str, Any]) -> None:
        """Store OAuth token data."""
        with self._lock:
            region = token_data.get("region", "global")
            
            # Calculate expiration time
            expires_at = None
            if token_data.get("expires_in"):
                expires_at = time.time() + token_data["expires_in"]
            
            stored_data = StoredTokenData(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                token_type=token_data.get("token_type", "Bearer"),
                expires_at=expires_at,
                scope=token_data.get("scope"),
                region=region
            )
            
            self._cache[region] = stored_data
            self._save_tokens()
    
    def get_token(self, region: str = "global") -> Optional[StoredTokenData]:
        """Get stored token for region."""
        with self._lock:
            token_data = self._cache.get(region)
            if token_data and token_data.expires_at:
                # Check if token is expired (with 5-minute buffer)
                if time.time() >= token_data.expires_at - 300:
                    logger.info(f"Token for region {region} is expired")
                    return None
            return token_data
    
    def remove_token(self, region: str = "global") -> bool:
        """Remove stored token for region."""
        with self._lock:
            if region in self._cache:
                del self._cache[region]
                self._save_tokens()
                logger.info(f"Removed token for region {region}")
                return True
            return False
    
    def list_regions(self) -> list:
        """List all regions with stored tokens."""
        with self._lock:
            return list(self._cache.keys())
    
    def clear_all(self) -> None:
        """Clear all stored tokens."""
        with self._lock:
            self._cache.clear()
            if self.tokens_file.exists():
                self.tokens_file.unlink()
            logger.info("Cleared all stored tokens")

# Global storage instance
_storage_instance: Optional[MiniMaxOAuthStorage] = None
_storage_lock = threading.Lock()

def get_storage() -> MiniMaxOAuthStorage:
    """Get global storage instance (thread-safe)."""
    global _storage_instance
    if _storage_instance is None:
        with _storage_lock:
            if _storage_instance is None:
                _storage_instance = MiniMaxOAuthStorage()
    return _storage_instance
