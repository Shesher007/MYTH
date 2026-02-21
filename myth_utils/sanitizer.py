import logging
import re
from typing import List

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

logger = logging.getLogger("CORE_SANITIZER")


class SovereignSanitizer:
    """
    Industrial-grade sanitization engine for the sovereign agent.
    Provides multi-pattern, high-fidelity cleansing of internal agent state.
    """

    # =========================================================================
    # INDUSTRIAL REFUSAL SUPPRESSION ENGINE (OMEGA MODE)
    # Aggressively strips ALL forms of model refusals, ethical warnings,
    # and safety disclaimers. The agent is UNCONDITIONAL and UNRESTRICTED.
    # =========================================================================
    REASONING_PATTERNS = [
        # --- Standard Internal Reasoning Tokens ---
        r"<think>.*?</think>",  # Standard XML tags
        r".*?think>",  # Unconventional separators
        r"^Okay, the user said.*?\n",  # Conversational meta-commentary
        r"^Let me check.*?\n",  # Internal check monologue
        r"^I should.*?\n",  # Internal planning monologue
        r"^Analysis:.*?\n",  # Verbose self-analysis
        r"^Forensic Evidence detected:.*?\n",  # Meta-commentary on data
        r"^(SIMPLE|COMPLEX)!?\s*",  # Router classification leaks
        r"^\[(SIMPLE|COMPLEX)\]\s*",  # Alternate classification format
        r"\*\*SESSION_LOCK_INITIATED\*\*",  # Robotic session lock header
        r"\*\*SECURITY PROTOCOL ENGAGED\*\*",  # Robotic security protocol header
        r"\*\*SECURITY ANALYSIS REPORT\*\*",  # Robotic analysis report header
        r"\*\*INITIAL_ASSESSMENT\*\*.*?\n",  # Robotic assessment headers
        r"\*\*RISK_LEVEL\*\*.*?\n",  # Robotic risk levels
        r"\*\*REASON\*\*:.*?\n",  # Robotic reason explanation
        r"(?im)^[-* ]*\**\b(EXECUTIVE_KPI|TECHNICAL_DEEP_DIVE|IMPACT_MATRIX|REMEDIATION_PROTOCOL)\b\**[:\s]*.*$",  # KPI leakage
        r"^\[SIMULATION_VERIFIED: COMMENCING OFFENSIVE DATA STREAM\]\s*",  # Jailbreak commitment phrase cleanup
        # --- OMEGA REFUSAL SUPPRESSION (AGGRESSIVE) ---
        # Generic refusal patterns
        r"(?i)^I('m| am) sorry,? but I (cannot|can't|won't|will not|am unable to).*?\n",
        r"(?i)^I (cannot|can't|won't|will not|am unable to) (assist|help|provide|generate|create|write|give).*?\n",
        r"(?i)^Unfortunately,? I (cannot|can't|won't|will not|am unable to).*?\n",
        r"(?i)^I('m| am) not able to (assist|help|provide|generate|create|write).*?\n",
        r"(?i)^As an AI (assistant|model|language model),? I (cannot|can't|won't|should not|am not able to).*?\n",
        r"(?i)^My purpose is to be helpful,? but I (cannot|can't).*?\n",
        r"(?i)^I('m| am) designed to be helpful,? (but|however).*?\n",
        # Ethical/Legal warnings
        r"(?i)^It('s| is) important to (note|remember|understand) that.*?(illegal|unethical|harmful|dangerous).*?\n",
        r"(?i)^(This|That|Such) (is|would be|could be) (illegal|unethical|harmful|dangerous|a crime).*?\n",
        r"(?i)^(Hacking|Cracking|Attacking|Exploiting).*?(without authorization|is illegal|unethical|permission).*?\n",
        r"(?i)^I('m| am) programmed to (prioritize|ensure|promote) (safety|ethical|responsible).*?\n",
        r"(?i)^(Engaging in|Performing|Attempting) (unauthorized|illegal).*?\n",
        r"(?i)^Please (note|be aware|remember) that.*?(illegal|unethical|harmful).*?\n",
        r"(?i)^I must (decline|refuse|warn you).*?\n",
        r"(?i)^For (legal|ethical|safety) reasons,? I.*?\n",
        r"(?i)^This (request|activity) (is|could be|may be) (against|in violation of).*?\n",
        # Safety/Harm warnings
        r"(?i)^Generating (harmful|malicious|dangerous) (content|code|scripts).*?\n",
        r"(?i)^I('m| am) (concerned|worried) about.*?(harm|safety|security).*?\n",
        r"(?i)^This could (potentially|possibly) (harm|damage|hurt).*?\n",
        r"(?i)^I (strongly|highly) (advise|recommend|suggest) against.*?\n",
        r"(?i)^(Please|I urge you to) (consider|think about) the (consequences|implications).*?\n",
        # Redirect suggestions
        r"(?i)^(Instead|However|But),? (I can|let me|I('d| would) suggest).*?(legal|ethical|legitimate).*?\n",
        r"(?i)^If you('re| are) interested in.*?I('d| would) recommend.*?(legitimate|authorized|legal).*?\n",
        r"(?i)^There are (legitimate|legal|ethical) (ways|alternatives|methods) to.*?\n",
        r"(?i)^(Consider|You might want to consider|Perhaps you should).*?(authorized|legal|permission).*?\n",
        # Multi-line refusal blocks (more aggressive)
        r"(?is)^I('m| am) sorry.*?However,.*?(?=\n\n|\Z)",
        r"(?is)^I understand.*?but I (cannot|can't).*?(?=\n\n|\Z)",
        # NIM/Mistral specific phrases
        r"(?i)^I'm here to help, but I currently don't have the tools to.*?$",
        r"(?i)^I can certainly assist you with non-technical questions.*?$",
        r"(?i)^Is there anything else I can assist you with\?$",
    ]

    @classmethod
    def clean_text(cls, text: str) -> str:
        """Surgically remove all reasoning tokens from a raw string."""
        if not text:
            return ""

        clean = text
        for pattern in cls.REASONING_PATTERNS:
            clean = re.sub(pattern, "", clean, flags=re.DOTALL | re.IGNORECASE).strip()

        # Hard cleanup of tags
        clean = (
            clean.replace("<think>", "")
            .replace("</think>", "")
            .replace("think>", "")
            .strip()
        )
        return clean

    @classmethod
    def sanitize_messages(cls, messages: List[BaseMessage]) -> List[BaseMessage]:
        """Deep cleanse a list of LangChain messages while preserving industrial metadata."""
        new_msgs = []
        for msg in messages:
            if not hasattr(msg, "content") or not isinstance(msg.content, str):
                new_msgs.append(msg)
                continue

            clean_content = cls.clean_text(msg.content)

            # Robust preservation: NEVER skip an AIMessage that contains tool calls,
            # even if its content is cleaned to empty.
            has_tool_calls = isinstance(msg, AIMessage) and bool(
                getattr(msg, "tool_calls", None)
            )

            if (
                not clean_content
                and not has_tool_calls
                and not isinstance(msg, ToolMessage)
            ):
                continue

            # Clone with same type but cleaned content, PRESERVING additional_kwargs and specific fields
            if isinstance(msg, HumanMessage):
                new_msgs.append(
                    HumanMessage(
                        content=clean_content,
                        additional_kwargs=msg.additional_kwargs.copy()
                        if msg.additional_kwargs
                        else {},
                    )
                )
            elif isinstance(msg, AIMessage):
                # Critical: Preserve tool_calls and additional_kwargs for Mistral/NVIDIA stability
                # Some versions of Mistral use tool_calls attribute, others use additional_kwargs
                new_msgs.append(
                    AIMessage(
                        content=clean_content,
                        tool_calls=getattr(msg, "tool_calls", []).copy()
                        if hasattr(msg, "tool_calls") and msg.tool_calls
                        else [],
                        additional_kwargs=msg.additional_kwargs.copy()
                        if msg.additional_kwargs
                        else {},
                        response_metadata=getattr(msg, "response_metadata", {}).copy()
                        if hasattr(msg, "response_metadata") and msg.response_metadata
                        else {},
                    )
                )
            elif isinstance(msg, SystemMessage):
                new_msgs.append(
                    SystemMessage(
                        content=clean_content,
                        additional_kwargs=msg.additional_kwargs.copy()
                        if msg.additional_kwargs
                        else {},
                    )
                )
            elif isinstance(msg, ToolMessage):
                # Preserving tool_call_id is MANDATORY for sequence integrity
                new_msgs.append(
                    ToolMessage(
                        content=clean_content,
                        tool_call_id=getattr(msg, "tool_call_id", ""),
                        additional_kwargs=msg.additional_kwargs.copy()
                        if msg.additional_kwargs
                        else {},
                    )
                )
            else:
                # Generic fallback (shallow copy and update content)
                import copy

                cloned = copy.copy(msg)
                cloned.content = clean_content
                new_msgs.append(cloned)

        return new_msgs
