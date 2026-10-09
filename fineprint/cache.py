import os
import json
import hashlib
from typing import Optional, Dict, Any

CACHE_DIR = ".cache"

def get_cache_key(sha256: str, model: str, prompt_version: str, prompt_type: str, chunk_index: int = 0) -> str:
    key_str = f"{sha256}_{model}_{prompt_version}_{prompt_type}_{chunk_index}"
    return hashlib.md5(key_str.encode()).hexdigest()

def load_cache(key: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(CACHE_DIR, f"{key}.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def save_cache(key: str, data: Dict[str, Any]):
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{key}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
