#!/usr/bin/env python3
"""
Tests for MiniMax OAuth integration.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import time

from tools.minimax_oauth_tool import (
    MiniMaxOAuthError,
    minimax_oauth_initiate,
    minimax_oauth_token,
    minimax_oauth_refresh,
    minimax_oauth_revoke,
    _validate_region,
    _get_minimax_config
)
from tools.minimax_oauth_storage import MiniMaxOAuthStorage, StoredTokenData

class TestMiniMaxOAuthTool:
    """Test MiniMax OAuth tool functions."""
    
    def test_validate_region_valid(self):
        """Test region validation with valid inputs."""
        assert _validate_region("global") == "global"
        assert _validate_region("cn") == "cn"
    
    def test_validate_region_invalid(self):
        """Test region validation with invalid inputs."""
        with pytest.raises(MiniMaxOAuthError, match="Invalid region"):
            _validate_region("invalid")
        with pytest.raises(MiniMaxOAuthError, match="Invalid region"):
            _validate_region("")
    
    def test_get_minimax_config(self):
        """Test configuration loading."""
        config = _get_minimax_config("global")
        assert config.region == "global"
        assert config.client_id == "78257093-7e40-4613-99e0-527b14b39113"
        assert "openid" in config.scopes
        
        config_cn = _get_minimax_config("cn")
        assert config_cn.region == "cn"
        assert "minimaxi.com" in config_cn.auth_url
    
    def test_minimax_oauth_initiate_success(self):
        """Test successful OAuth initiation."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "device_code": "test_device_code",
            "user_code": "TEST123",
            "verification_uri_complete": "https://example.com/verify",
            "expires_in": 600,
            "interval": 5
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            result = minimax_oauth_initiate("global")
            
            assert result["device_code"] == "test_device_code"
            assert result["user_code"] == "TEST123"
            assert result["region"] == "global"
    
    def test_minimax_oauth_initiate_failure(self):
        """Test OAuth initiation failure."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Invalid client"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            with pytest.raises(MiniMaxOAuthError, match="Device authorization failed"):
                minimax_oauth_initiate("global")
    
    def test_minimax_oauth_token_success(self):
        """Test successful token exchange."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile model.completion"
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            result = minimax_oauth_token("test_device_code", "global")
            
            assert result["access_token"] == "test_access_token"
            assert result["refresh_token"] == "test_refresh_token"
            assert result["region"] == "global"

class TestMiniMaxOAuthStorage:
    """Test MiniMax OAuth storage functionality."""
    
    def test_storage_initialization(self):
        """Test storage initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = MiniMaxOAuthStorage(Path(temp_dir))
            assert storage.storage_dir == Path(temp_dir)
            assert storage.tokens_file.exists() is False
    
    def test_store_and_get_token(self):
        """Test storing and retrieving tokens."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = MiniMaxOAuthStorage(Path(temp_dir))
            
            token_data = {
                "access_token": "test_token",
                "refresh_token": "test_refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile",
                "region": "global"
            }
            
            storage.store_token(token_data)
            
            retrieved = storage.get_token("global")
            assert retrieved is not None
            assert retrieved.access_token == "test_token"
            assert retrieved.refresh_token == "test_refresh"
            assert retrieved.region == "global"
    
    def test_token_expiration(self):
        """Test token expiration handling."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = MiniMaxOAuthStorage(Path(temp_dir))
            
            # Store expired token
            token_data = {
                "access_token": "expired_token",
                "expires_in": -3600,  # Already expired
                "region": "global"
            }
            storage.store_token(token_data)
            
            retrieved = storage.get_token("global")
            assert retrieved is None  # Should return None for expired token
    
    def test_remove_token(self):
        """Test token removal."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = MiniMaxOAuthStorage(Path(temp_dir))
            
            token_data = {
                "access_token": "test_token",
                "region": "global"
            }
            storage.store_token(token_data)
            
            assert storage.remove_token("global") is True
            assert storage.get_token("global") is None
            assert storage.remove_token("global") is False  # Already removed
    
    def test_persistence(self):
        """Test token persistence across storage instances."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Store token in first instance
            storage1 = MiniMaxOAuthStorage(Path(temp_dir))
            token_data = {
                "access_token": "persistent_token",
                "region": "global"
            }
            storage1.store_token(token_data)
            
            # Retrieve from second instance
            storage2 = MiniMaxOAuthStorage(Path(temp_dir))
            retrieved = storage2.get_token("global")
            assert retrieved is not None
            assert retrieved.access_token == "persistent_token"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
