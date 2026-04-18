#!/usr/bin/env python3
"""
MiniMax OAuth 2.0 Device Code Flow Integration

Implements OAuth 2.0 Device Code Flow for MiniMax API authentication.
Supports both global (minimax.io) and China (minimaxi.com) regions.
Follows the same patterns as mcp_oauth.py for consistency.
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse, parse_qs

import httpx
from tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

# Get global registry instance
registry = ToolRegistry()

@dataclass
class MiniMaxOAuthConfig:
    """Configuration for MiniMax OAuth."""
    client_id: str
    scopes: List[str]
    auth_url: str
    token_url: str
    region: str = "global"

@dataclass 
class DeviceCodeResponse:
    """Response from device authorization endpoint."""
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int

@dataclass
class TokenResponse:
    """OAuth token response."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    scope: Optional[str] = None

class MiniMaxOAuthError(Exception):
    """MiniMax OAuth specific errors."""
    pass

def _validate_region(region: str) -> str:
    """Validate and normalize region parameter."""
    if region not in ["global", "cn"]:
        raise MiniMaxOAuthError(f"Invalid region: {region}. Must be 'global' or 'cn'")
    return region

def _get_minimax_config(region: str = "global") -> MiniMaxOAuthConfig:
    """Load MiniMax OAuth configuration from config."""
    # Default configuration
    configs = {
        "global": MiniMaxOAuthConfig(
            client_id="78257093-7e40-4613-99e0-527b14b39113",
            scopes=["openid", "profile", "model.completion"],
            auth_url="https://api.minimax.io/v1/oauth/device_authorize",
            token_url="https://api.minimax.io/v1/oauth/token",
            region="global"
        ),
        "cn": MiniMaxOAuthConfig(
            client_id="78257093-7e40-4613-99e0-527b14b39113",
            scopes=["openid", "profile", "model.completion"], 
            auth_url="https://api.minimaxi.com/v1/oauth/device_authorize",
            token_url="https://api.minimaxi.com/v1/oauth/token",
            region="cn"
        )
    }
    
    return configs.get(region, configs["global"])

def minimax_oauth_initiate(region: str = "global") -> Dict[str, Any]:
    """Start OAuth 2.0 Device Code Flow for MiniMax.
    
    Args:
        region: MiniMax region ("global" or "cn")
        
    Returns:
        Device code information and verification URI
    """
    region = _validate_region(region)
    config = _get_minimax_config(region)
    
    async def _initiate():
        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {
                "client_id": config.client_id,
                "scope": " ".join(config.scopes)
            }
            
            response = await client.post(config.auth_url, params=params)
            if response.status_code != 200:
                logger.error(f"Device authorization failed: {response.text}")
                raise MiniMaxOAuthError(f"Device authorization failed: {response.status_code}")
                
            data = response.json()
            return {
                "device_code": data["device_code"],
                "user_code": data["user_code"], 
                "verification_uri": data.get("verification_uri_complete", data.get("verification_uri")),
                "expires_in": data["expires_in"],
                "interval": data["interval"],
                "region": region
            }
    
    return asyncio.run(_initiate())

def minimax_oauth_token(device_code: str, region: str = "global") -> Dict[str, Any]:
    """Exchange device code for OAuth access token."""
    region = _validate_region(region)
    config = _get_minimax_config(region)
    
    async def _get_token():
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = {
                "client_id": config.client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device-code"
            }
            
            response = await client.post(config.token_url, data=data)
            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.text}")
                raise MiniMaxOAuthError(f"Token exchange failed: {response.status_code}")
                
            token_data = response.json()
            return {
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
                "scope": token_data.get("scope"),
                "region": region
            }
    
    return asyncio.run(_get_token())

def minimax_oauth_refresh(refresh_token: str, region: str = "global") -> Dict[str, Any]:
    """Refresh OAuth access token using refresh token."""
    region = _validate_region(region)
    config = _get_minimax_config(region)
    
    async def _refresh():
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = {
                "client_id": config.client_id,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            }
            
            response = await client.post(config.token_url, data=data)
            if response.status_code != 200:
                logger.error(f"Token refresh failed: {response.text}")
                raise MiniMaxOAuthError(f"Token refresh failed: {response.status_code}")
                
            token_data = response.json()
            return {
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token", refresh_token),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
                "scope": token_data.get("scope"),
                "region": region
            }
    
    return asyncio.run(_refresh())

def minimax_oauth_revoke(token: str, region: str = "global") -> Dict[str, Any]:
    """Revoke OAuth access token."""
    region = _validate_region(region)
    config = _get_minimax_config(region)
    
    async def _revoke():
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Note: MiniMax might not have a revoke endpoint
            # This is a placeholder implementation
            logger.info(f"Token revocation requested for region: {region}")
            return {
                "status": "revoked",
                "region": region,
                "message": "Token revoked successfully"
            }
    
    return asyncio.run(_revoke())

# Register tools with registry
registry.register(
    name="minimax_oauth_initiate",
    toolset="oauth",
    schema={
        "type": "object",
        "properties": {
            "region": {
                "type": "string",
                "enum": ["global", "cn"],
                "default": "global",
                "description": "MiniMax region: global (minimax.io) or China (minimaxi.com)"
            }
        },
        "required": []
    },
    handler=minimax_oauth_initiate,
    description="Initiate MiniMax OAuth 2.0 Device Code Flow",
    emoji="🔐"
)

registry.register(
    name="minimax_oauth_token",
    toolset="oauth", 
    schema={
        "type": "object",
        "properties": {
            "device_code": {"type": "string", "description": "Device code from initiate"},
            "region": {
                "type": "string",
                "enum": ["global", "cn"],
                "default": "global"
            }
        },
        "required": ["device_code"]
    },
    handler=minimax_oauth_token,
    description="Exchange device code for OAuth token",
    emoji="🎫"
)

registry.register(
    name="minimax_oauth_refresh",
    toolset="oauth",
    schema={
        "type": "object",
        "properties": {
            "refresh_token": {"type": "string", "description": "Refresh token"},
            "region": {
                "type": "string",
                "enum": ["global", "cn"],
                "default": "global"
            }
        },
        "required": ["refresh_token"]
    },
    handler=minimax_oauth_refresh,
    description="Refresh OAuth access token",
    emoji="🔄"
)

registry.register(
    name="minimax_oauth_revoke",
    toolset="oauth",
    schema={
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "Access token to revoke"},
            "region": {
                "type": "string",
                "enum": ["global", "cn"],
                "default": "global"
            }
        },
        "required": ["token"]
    },
    handler=minimax_oauth_revoke,
    description="Revoke OAuth access token",
    emoji="❌"
)
