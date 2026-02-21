import base64
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from myth_config import load_dotenv

load_dotenv()
from config_loader import agent_config  # noqa: E402

logger = logging.getLogger(__name__)

# Industrial Grade limits
MAX_AUDIO_SIZE_MB = 25


class AudioProcessor:
    """
    Advanced audio processing and transcription using Mistral Voxtral APIs.
    Optimized for security log analysis and voice forensics.
    """

    def __init__(self, mistral_api_key: Optional[str] = None):
        from myth_llm import ReliableLLM

        # Initialize Voxtral model using ReliableLLM for industrial consistency
        self.model_id = agent_config.models.audio
        self.audio_model = ReliableLLM(
            provider="mistral", model_name=self.model_id, temperature=0.1
        )
        logger.info(f"🎙️ [AUDIO] AudioProcessor initialized with model: {self.model_id}")

    def _encode_audio_to_base64(self, audio_path: str) -> str:
        """Encode audio file to base64 string"""
        with open(audio_path, "rb") as audio_file:
            return base64.b64encode(audio_file.read()).decode("utf-8")

    async def transcribe_and_analyze(
        self, audio_path: str, prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Transcribe audio and perform security-focused sentiment/content analysis (Async).
        """
        try:
            # Dynamic MIME detection
            ext = Path(audio_path).suffix.lower()
            # mime_type = mime_map.get(ext, 'audio/wav')  # F841 fixed: unused
            # Industrial grade: Size check to prevent memory crash
            file_size_mb = os.path.getsize(audio_path) / (1024 * 1024)
            if file_size_mb > MAX_AUDIO_SIZE_MB:
                return {
                    "success": False,
                    "error": f"Audio file too large ({file_size_mb:.2f}MB). Max: {MAX_AUDIO_SIZE_MB}MB",
                }

            base64_audio = self._encode_audio_to_base64(audio_path)

            # Formulate industrial audio analysis prompt
            default_prompt = (
                "Transcribe this audio log exactly. "
                "Then, identify any technical keywords, passwords, server names, or security incidents mentioned. "
                "Provide a 'Security Sentiment' rating (Low/Medium/High Risk)."
            )

            # Industrial Grade: Bypass LangChain's message normalization which
            # currently corrupts Mistral's beta input_audio schema.
            payload = {
                "model": self.model_id,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt or default_prompt},
                            {
                                "type": "input_audio",
                                "input_audio": {
                                    "data": base64_audio,
                                    "format": ext.strip(".") if ext else "wav",
                                },
                            },
                        ],
                    }
                ],
                "temperature": 0.1,
                "safe_prompt": False,
            }

            logger.info(
                "📤 [AUDIO_API] Sending direct multimodal request to Mistral..."
            )

            # Industrial Grade: Exponential Backoff for 429 Rate Limits
            max_retries = 5
            delays = [2, 5, 10, 20, 30]  # Adaptive backoff strategy

            for attempt in range(max_retries + 1):
                # Use the existing httpx client from the underlying model to preserve config/pool
                client = self.audio_model.underlying_model.async_client
                response = await client.post("/chat/completions", json=payload)

                if response.status_code == 429:
                    if attempt < max_retries:
                        delay = delays[attempt] if attempt < len(delays) else 30
                        logger.warning(
                            f"⚠️ [AUDIO_API] Rate limit hit (429). Retrying in {delay}s... (Attempt {attempt + 1}/{max_retries})"
                        )
                        import asyncio

                        await asyncio.sleep(delay)
                        continue
                    else:
                        error_msg = response.text
                        logger.error(
                            "❌ [AUDIO_API] Max retries exceeded for rate limit."
                        )
                        return {
                            "success": False,
                            "error": f"API Rate Limit Exceeded after {max_retries} retries. Please check your Mistral quota.",
                        }

                if response.status_code != 200:
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("message", response.text)
                    except Exception:
                        error_msg = response.text

                    file_size = os.path.getsize(audio_path)
                    logger.error(
                        f"Mistral Audio API reported error {response.status_code}: {error_msg} | Size: {file_size}b"
                    )
                    return {
                        "success": False,
                        "error": f"Mistral API Error {response.status_code}: {error_msg}",
                    }

                # If we get here, success
                break

            data = response.json()
            if "choices" not in data or not data["choices"]:
                return {
                    "success": False,
                    "error": "Invalid API response: No choices returned",
                }

            report = data["choices"][0]["message"]["content"]

            return {
                "success": True,
                "transcription_report": report,
                "audio_path": audio_path,
                "model": self.model_id,
                "usage": data.get("usage", {}),
            }
        except Exception as e:
            logger.error(f"Mistral Audio API call failed: {e}")
            return {"success": False, "error": f"Internal Error: {str(e)}"}

    async def detect_voice_alerts(self, audio_path: str) -> Dict[str, Any]:
        """Specific tool-like call for rapid alert detection (Async)."""
        prompt = "Listen for any audible alarms, shouting, or mentions of 'breach', 'intrusion', or 'compromise'. List them as alerts."
        return await self.transcribe_and_analyze(audio_path, prompt)
