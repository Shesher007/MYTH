import base64
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain_core.messages import HumanMessage

from config_loader import agent_config
from myth_config import load_dotenv

load_dotenv()
from tenacity import retry, stop_after_attempt, wait_exponential  # noqa: E402

logger = logging.getLogger(__name__)

# Industrial Grade limits
MAX_IMAGE_SIZE_MB = 15


class ImageProcessor:
    """Advanced image processing using NVIDIA NIM Vision APIs (API-Only)"""

    def __init__(
        self, nvidia_api_key: Optional[str] = None, vision_model: Optional[str] = None
    ):
        from myth_llm import ReliableLLM

        self.vision_model_id = vision_model or agent_config.models.image
        self.vision_model = ReliableLLM(
            provider="nvidia",
            model_name=self.vision_model_id,
            temperature=0.2,
            max_tokens=1024,
        )
        logger.info(
            f"🎨 [VISION] ImageProcessor initialized with node: {self.vision_model_id}"
        )

    def encode_image_to_base64(self, image_path: str) -> str:
        """Encode image to base64 with local pre-scaling for speed and token efficiency"""
        import io

        from PIL import Image

        file_size = os.path.getsize(image_path)

        # Ultra Upgrade: Local Pre-scaling
        # If image > 2MB, resize to 1024px max dimension
        if file_size > 2 * 1024 * 1024:
            logger.info(f"⚡ [VISION] Pre-scaling large image: {Path(image_path).name}")
            with Image.open(image_path) as img:
                # Convert to RGB if needed
                if img.mode in ("RGBA", "P"):
                    img = img.convert("RGB")

                img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
                buffered = io.BytesIO()
                img.save(buffered, format="JPEG", quality=85, optimize=True)
                return base64.b64encode(buffered.getvalue()).decode("utf-8")

        # Standard encoding for small images
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode("utf-8")

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _call_vision_api(self, image_path: str, prompt: str) -> str:
        """Helper to call Vision API with retries"""
        try:
            base64_image = self.encode_image_to_base64(image_path)

            message = HumanMessage(
                content=[
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
                    },
                ]
            )

            response = self.vision_model.invoke([message])
            return response.content
        except Exception as e:
            logger.error(f"Vision API call failed: {e}")
            return f"Error: {str(e)}"

    def generate_image_caption(self, image_path: str) -> Dict[str, Any]:
        """Generate detailed caption for image using Vision API"""
        prompt = "Provide a high-detail, technical description of this image. Focus on components, environment, and any text visible."
        caption = self._call_vision_api(image_path, prompt)

        return {"primary_caption": caption, "image_path": image_path}

    def detect_objects(
        self, image_path: str, target_objects: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Detect objects in image using Vision API"""
        if not target_objects:
            target_objects = [
                "servers",
                "network gear",
                "computers",
                "people",
                "security cameras",
                "ID badges",
                "sensitive documents",
            ]

        prompt = f"List all detected objects in this image. Specifically look for: {', '.join(target_objects)}. Return as a bulleted list with brief descriptions."
        findings = self._call_vision_api(image_path, prompt)

        return {"detected_objects_summary": findings, "image_path": image_path}

    def extract_text_from_image(self, image_path: str) -> Dict[str, Any]:
        """Extract text using Vision API (Superior to local OCR)"""
        prompt = "Extract all text from this image exactly as written. If there is sensitive information (passwords, keys), highlight it."
        text = self._call_vision_api(image_path, prompt)

        return {"extracted_text": text, "image_path": image_path}

    def security_analysis(self, image_path: str) -> Dict[str, Any]:
        """Perform security-focused image analysis using Vision API"""
        prompt = """Perform a RED TEAM SECURITY ANALYSIS of this image. 
        Look for:
        1. Exposed passwords, tokens, or configuration files.
        2. Visible network hardware (brands, models).
        3. Security vulnerabilities (physical or digital).
        4. People or ID badges that could be used for social engineering.
        
        Provide a list of 'Critical Findings' and 'Recommendations'."""

        analysis = self._call_vision_api(image_path, prompt)

        # Parse for simple concerns count (heuristic)
        security_concerns = [
            line
            for line in analysis.split("\n")
            if "finding" in line.lower() or "critical" in line.lower()
        ]

        return {
            "analysis_report": analysis,
            "security_concerns": security_concerns,
            "total_concerns": len(security_concerns),
            "image_path": image_path,
        }

    def analyze_image_similarity(
        self, image1_path: str, image2_path: str
    ) -> Dict[str, Any]:
        """Analyze similarity between two images using Vision API"""
        try:
            b64_1 = self.encode_image_to_base64(image1_path)
            b64_2 = self.encode_image_to_base64(image2_path)

            prompt = "Compare these two images and describe their similarities and differences. Are they of the same object or scene? Give a similarity score from 0 to 100."

            message = HumanMessage(
                content=[
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{b64_1}"},
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{b64_2}"},
                    },
                ]
            )

            response = self.vision_model.invoke([message])
            return {
                "comparison": response.content,
                "image1": image1_path,
                "image2": image2_path,
            }
        except Exception as e:
            logger.error(f"Image similarity analysis failed: {e}")
            return {"error": str(e)}
