import os
import re
import time
from typing import List, Dict, Any, Optional
from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from openai import RateLimitError, APIError, AuthenticationError, APIConnectionError

# Try to load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class LLMFallbackManager:
    """
    Manages LLM API requests with automated fallback across:
    1. Multiple Models (e.g., openai/gpt-oss-120b -> qwen/qwen3.8-27b -> openai/gpt-oss-20b)
    2. Multiple API Keys (rotates when rate limits or quota exhaustion is encountered)
    3. Multiple Endpoints (if specified)
    """

    def __init__(self):
        self.api_base = os.getenv("LLAMA3_API_BASE", "https://api.groq.com/openai/v1").strip()
        self.primary_model = os.getenv("LLAMA3_MODEL_NAME", "openai/gpt-oss-120b").strip()
        
        # Parse fallback models
        fallback_models_env = os.getenv("FALLBACK_MODELS", "qwen/qwen3.8-27b,openai/gpt-oss-20b,allam-2-7b")
        raw_models = [self.primary_model] + [m.strip() for m in re.split(r'[,;|\n]+', fallback_models_env) if m.strip()]
        # Deduplicate while preserving order
        self.models: List[str] = []
        for m in raw_models:
            if m and m not in self.models:
                self.models.append(m)

        # Parse API keys (support single key, comma-separated keys, and FALLBACK_API_KEYS)
        primary_key = os.getenv("LLAMA3_API_KEY", "EMPTY").strip()
        fallback_keys_env = os.getenv("FALLBACK_API_KEYS", "")
        raw_keys = [k.strip() for k in re.split(r'[,;|\n]+', primary_key + "," + fallback_keys_env) if k.strip()]
        self.api_keys: List[str] = []
        for k in raw_keys:
            if k and k not in self.api_keys:
                self.api_keys.append(k)
        if not self.api_keys:
            self.api_keys = ["EMPTY"]

        self.current_model_index = 0
        self.current_key_index = 0
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2048"))

    def get_status(self) -> Dict[str, Any]:
        """Returns the current active model, key index, and fallback chain."""
        return {
            "active_model": self.models[self.current_model_index] if self.models else "None",
            "all_models": self.models,
            "total_keys": len(self.api_keys),
            "current_key_index": self.current_key_index + 1,
            "api_base": self.api_base
        }

    def _create_chat_client(self, model: str, api_key: str) -> ChatOpenAI:
        return ChatOpenAI(
            model=model,
            openai_api_base=self.api_base,
            openai_api_key=api_key,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout=45.0,
            max_retries=1
        )

    def invoke(self, messages: Any, **kwargs) -> AIMessage:
        """
        Executes an LLM chat invocation with automated fallback across available
        models and API keys if quota, rate limit (HTTP 429), or errors occur.
        """
        last_error = None
        total_models = len(self.models)
        total_keys = len(self.api_keys)
        
        # Format messages if string was passed
        if isinstance(messages, str):
            messages = [HumanMessage(content=messages)]

        # Try combinations of (Key, Model) starting from current or next available
        attempts = 0
        max_attempts = total_models * total_keys

        for key_offset in range(total_keys):
            key_idx = (self.current_key_index + key_offset) % total_keys
            api_key = self.api_keys[key_idx]

            for model_offset in range(total_models):
                model_idx = (self.current_model_index + model_offset) % total_models
                model_name = self.models[model_idx]
                attempts += 1

                try:
                    masked_key = api_key[:7] + "..." + api_key[-4:] if len(api_key) > 12 else "key"
                    client = self._create_chat_client(model_name, api_key)
                    
                    # Execute the LLM call
                    response = client.invoke(messages, **kwargs)

                    # Update current indices to the working combination
                    self.current_model_index = model_idx
                    self.current_key_index = key_idx
                    return response

                except Exception as exc:
                    err_str = str(exc)
                    is_rate_limit = (
                        "429" in err_str or
                        "rate_limit" in err_str.lower() or
                        "quota" in err_str.lower() or
                        "tokens per minute" in err_str.lower() or
                        "requests per day" in err_str.lower()
                    )
                    is_auth_error = (
                        "401" in err_str or
                        "invalid api key" in err_str.lower() or
                        "authentication" in err_str.lower()
                    )
                    is_not_found = "404" in err_str or "does not exist" in err_str.lower()

                    last_error = exc
                    masked_key = api_key[:7] + "..." + api_key[-4:] if len(api_key) > 12 else "key"

                    if is_rate_limit:
                        reason = "Rate Limit / Quota Exceeded (429)"
                    elif is_auth_error:
                        reason = "API Key Expired / Auth Error (401)"
                    elif is_not_found:
                        reason = "Model not found / No access (404)"
                    else:
                        reason = f"API Error: {err_str[:60]}"

                    print(f"⚠️  [LLM Auto-Fallback] Model '{model_name}' on Key #{key_idx + 1} failed: {reason}")
                    
                    # If this was not the last model in the loop, announce the fallback
                    next_model_idx = (model_idx + 1) % total_models
                    next_model = self.models[next_model_idx]
                    print(f"🔄 [LLM Auto-Fallback] Switching to fallback model: '{next_model}'...")
                    time.sleep(0.5)

        # If all combinations failed, raise the last exception
        print(f"❌ [LLM Error] All {attempts} model/key fallback attempts failed.")
        raise last_error if last_error else RuntimeError("All fallback models and API keys failed.")

# Global singleton fallback manager
fallback_llm = LLMFallbackManager()
