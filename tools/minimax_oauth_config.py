#!/usr/bin/env python3
"""MiniMax OAuth Configuration Management"""

import os
from dataclasses import dataclass
from typing import List

@dataclass
class MiniMaxRegionConfig:
    client_id: str
    scopes: List[str]
    auth_url: str
    token_url: str
    region: str = "global"

def get_region_config(region: str) -> MiniMaxRegionConfig:
    """Get configuration for specific region with env var support."""
    
    # Environment variables take precedence
    if region == "global":
        client_id = os.getenv("MINIMAX_CLIENT_ID", "78257093-7e40-4613-99e0-527b14b39113")
        auth_url = os.getenv("MINIMAX_AUTH_URL", "https://api.minimax.io/v1/oauth/device_authorize")
        token_url = os.getenv("MINIMAX_TOKEN_URL", "https://api.minimax.io/v1/oauth/token")
    elif region == "cn":
        client_id = os.getenv("MINIMAX_CN_CLIENT_ID", "78257093-7e40-4613-99e0-527b14b39113")
        auth_url = os.getenv("MINIMAX_CN_AUTH_URL", "https://api.minimaxi.com/v1/oauth/device_authorize")
        token_url = os.getenv("MINIMAX_CN_TOKEN_URL", "https://api.minimaxi.com/v1/oauth/token")
    else:
        raise ValueError(f"Invalid region: {region}")
    
    scopes = ["openid", "profile", "model.completion"]
    
    return MiniMaxRegionConfig(
        client_id=client_id,
        scopes=scopes,
        auth_url=auth_url,
        token_url=token_url,
        region=region
    )
