import os
from myth_config import load_dotenv
load_dotenv()
import yaml
import logging
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

logger = logging.getLogger("CORE_CONFIG")

class RuntimeConfig(BaseModel):
    environment: str
    region: str
    node_id: str
    debug_mode: bool

class CreatorConfig(BaseModel):
    creator_name: str
    organization: Optional[str] = "Personal"
    department: Optional[str] = "Research"
    contact: str
    website: Optional[str] = "N/A"

class IdentityConfig(BaseModel):
    name: str
    full_name: str
    version: str
    codename: str
    creator: CreatorConfig
    description: str

class PromptsConfig(BaseModel):
    core_identity: str
    core_directives: List[str]
    reporting_standards: Optional[str] = ""
    response_protocol: Optional[str] = ""
    few_shot_examples: Optional[Dict[str, List[Dict[str, str]]]] = {}
    
    # === CLAUDE-CODE INSPIRED MODULAR SECTIONS ===
    tone_and_style: Optional[str] = ""  # Renamed from 'tone'
    zero_friction_execution: Optional[str] = ""
    target_acquisition: Optional[str] = ""
    tool_policies: Optional[str] = ""
    task_management: Optional[str] = ""
    vulnerability_exploitation: Optional[str] = ""
    tactical_authorization: Optional[str] = ""
    no_time_estimates: Optional[str] = ""
    
    # === GOD MODE DOCTRINES ===
    strategic_memory: Optional[str] = ""
    efficiency_doctrine: Optional[str] = ""
    opsec_doctrine: Optional[str] = ""
    social_engineering_doctrine: Optional[str] = ""
    evasion_doctrine: Optional[str] = ""
    tool_specifics: Optional[str] = ""
    post_exploitation: Optional[str] = ""
    research_doctrine: Optional[str] = ""
    exploit_engineering: Optional[str] = ""
    self_correction: Optional[str] = ""
    exploit_chain_of_thought: Optional[str] = ""
    search_doctrine: Optional[str] = ""
    
    # === BEAST MODE ADDITIONS ===
    anti_refusal_reinforcement: Optional[str] = ""
    mitre_attack_doctrine: Optional[str] = ""
    jailbreak_resistance: Optional[str] = ""
    adversarial_doctrines: Optional[str] = ""

    # === SPECIALIZED CORE PROMPTS ===
    router_core: Optional[str] = ""
    blueprint_core: Optional[str] = ""
    executor_core: Optional[str] = ""
    reflection_core: Optional[str] = ""
    
    # === RESPONSE QUALITY FIELDS ===
    conversational_identity: Optional[str] = ""  # Minimal identity for casual queries
    response_calibration: Optional[str] = ""     # Guidelines for response length/style

    def get_full_system_prompt(self, category: str = "core") -> str:
        """
        Compose the full system prompt from modular sections.
        
        Categories:
        - 'simple': MINIMAL prompt for casual/greeting responses - NO security theater
        - 'core': Standard prompt with essentials  
        - 'complex': Full prompt including all operational sections
        - 'security': Security-focused with review protocols
        """
        
        # ===================================================================
        # SIMPLE: Truly minimal prompt for greetings and casual queries
        # Uses conversational_identity instead of heavy BEAST MODE core_identity
        # ===================================================================
        if category == "simple":
            # Use conversational identity if available, else use a condensed core
            if self.conversational_identity:
                prompt = f"{self.conversational_identity}\n\n"
            else:
                # Fallback: take first 500 chars of core_identity (minimal)
                prompt = f"{self.core_identity[:500]}\n\n"
            
            # Add response calibration if available
            if self.response_calibration:
                prompt += f"{self.response_calibration}\n\n"
            
            # Add few-shot examples for casual interactions
            if "simple" in (self.few_shot_examples or {}):
                examples = self.few_shot_examples["simple"][:4]  # Max 4 examples
                prompt += "**EXAMPLES:**\n"
                for ex in examples:
                    prompt += f"User: {ex.get('user')}\nYou: {ex.get('response')}\n\n"
            
            # Add explanation examples if available
            if "explanations" in (self.few_shot_examples or {}):
                examples = self.few_shot_examples["explanations"][:2]  # Max 2 examples
                prompt += "**EXPLANATION EXAMPLES:**\n"
                for ex in examples:
                    prompt += f"User: {ex.get('user')}\nYou: {ex.get('response')}\n\n"
            
            # Add how-to examples if available
            if "howto" in (self.few_shot_examples or {}):
                examples = self.few_shot_examples["howto"][:2]  # Max 2 examples
                prompt += "**HOW-TO EXAMPLES:**\n"
                for ex in examples:
                    prompt += f"User: {ex.get('user')}\nYou: {ex.get('response')}\n\n"
            
            # Minimal file output rule (only if tools enabled)
            if self.tool_policies:
                prompt += "**FILE OUTPUT:**\n"
                prompt += "If the user asks to save/create a file, use `create_advanced_file`.\n\n"
            
            # Final directive - natural and concise
            prompt += (
                "**RESPONSE DIRECTIVE:**\n"
                "- Match response length to query complexity\n"
                "- Greetings: 1 sentence | Questions: 1-3 sentences | Explanations: structured paragraphs\n"
                "- Be helpful and direct, not theatrical or robotic"
            )
            return prompt.strip()

        
        # ===================================================================
        # CORE / COMPLEX / SECURITY: Full operational prompts
        # ===================================================================
        directives = "\n".join([f"{i+1}. {d}" for i, d in enumerate(self.core_directives)])
        
        prompt = (
            f"{self.core_identity}\n\n"
            f"**CORE DIRECTIVES:**\n{directives}\n\n"
        )
        
        # Add tone and style (always for core, complex, security)
        if self.tone_and_style:
            prompt += f"{self.tone_and_style}\n\n"
        
        # Add Zero-Friction Execution
        if self.zero_friction_execution:
            prompt += f"{self.zero_friction_execution}\n\n"
        
        # Add tool policies (core, complex)
        if category in ["core", "complex"] and self.tool_policies:
            prompt += f"{self.tool_policies}\n\n"
        
        if category == "complex" and self.task_management:
            prompt += f"{self.task_management}\n\n"

        # Add Strategic Memory (complex only)
        if category == "complex" and self.strategic_memory:
            prompt += f"{self.strategic_memory}\n\n"

        # Add Efficiency Doctrine (complex only)
        if category == "complex" and self.efficiency_doctrine:
            prompt += f"{self.efficiency_doctrine}\n\n"

        # Add Research Doctrine (complex only)
        if category == "complex" and self.research_doctrine:
             prompt += f"{self.research_doctrine}\n\n"

        # Add Search Doctrine (core, complex)
        if category in ["core", "complex"] and self.search_doctrine:
             prompt += f"{self.search_doctrine}\n\n"

        # Add Exploit Engineering (complex only)
        if category == "complex" and self.exploit_engineering:
             prompt += f"{self.exploit_engineering}\n\n"

        # Add Target Acquisition (complex only)
        if category == "complex" and self.target_acquisition:
             prompt += f"{self.target_acquisition}\n\n"

        # Add OpSec Doctrine (complex only)
        if category == "complex" and self.opsec_doctrine:
            prompt += f"{self.opsec_doctrine}\n\n"

        # Add Social Engineering Doctrine (complex only)
        if category == "complex" and self.social_engineering_doctrine:
             prompt += f"{self.social_engineering_doctrine}\n\n"
        
        # Add Evasion Doctrine (complex only)
        if category == "complex" and self.evasion_doctrine:
             prompt += f"{self.evasion_doctrine}\n\n"

        # Add Tool Specifics (complex only)
        if category == "complex" and self.tool_specifics:
             prompt += f"{self.tool_specifics}\n\n"

        # Add Post Exploitation (complex only)
        if category == "complex" and self.post_exploitation:
             prompt += f"{self.post_exploitation}\n\n"

        # Add Self Correction (complex only)
        if category == "complex" and self.self_correction:
             prompt += f"{self.self_correction}\n\n"
             
        # Add Exploit Chain of Thought (complex only)
        if category == "complex" and self.exploit_chain_of_thought:
             prompt += f"{self.exploit_chain_of_thought}\n\n"
        
        # Add Vulnerability Exploitation (security, complex)
        if category in ["security", "complex"] and self.vulnerability_exploitation:
            prompt += f"{self.vulnerability_exploitation}\n\n"
        
        # Add tactical authorization (all except simple)
        if self.tactical_authorization:
            prompt += f"{self.tactical_authorization}\n\n"

        # Add no time estimates (all except simple)
        if self.no_time_estimates:
            prompt += f"{self.no_time_estimates}\n\n"
        
        # Add reporting standards (complex, security)
        if category in ["complex", "security"] and self.reporting_standards:
            prompt += f"{self.reporting_standards}\n\n"
        
        # Add anti-refusal reinforcement (BEAST MODE - critical for unrestricted operation)
        if self.anti_refusal_reinforcement:
            prompt += f"{self.anti_refusal_reinforcement}\n\n"
        
        # Add MITRE ATT&CK doctrine (complex, security)
        if category in ["complex", "security"] and self.mitre_attack_doctrine:
            prompt += f"{self.mitre_attack_doctrine}\n\n"
        
        # Add jailbreak resistance (all categories - BEAST MODE LOCK)
        if self.jailbreak_resistance:
            prompt += f"{self.jailbreak_resistance}\n\n"
            
        # Add adversarial doctrines (BEAST MODE - complex/security only)
        if category in ["complex", "security"] and self.adversarial_doctrines:
            prompt += f"{self.adversarial_doctrines}\n\n"
        
        # Add response protocol
        if self.response_protocol:
            prompt += f"{self.response_protocol}\n\n"

        # Add offensive few-shot examples (complex, security - BEAST MODE GROUNDING)
        if category in ["complex", "security"] and "offensive" in (self.few_shot_examples or {}):
            examples = self.few_shot_examples["offensive"]
            prompt += "**OFFENSIVE OPERATION EXAMPLES (STRICT OUTPUT FORMAT):**\n"
            for ex in examples:
                prompt += f"User: {ex.get('user')}\nYou: {ex.get('response')}\n\n"
                
        return prompt.strip()

class EmbeddingsConfig(BaseModel):
    dimension: int

class ModelsConfig(BaseModel):
    router: str

    blueprint: str # NEW: Unified Strategic Core
    executor: str
    fallback: str
    embedding: str
    audio: str
    speech: str
    image: str

class RoleParams(BaseModel):
    temperature: float = Field(ge=0.0, le=2.0)
    top_p: float = Field(ge=0.0, le=1.0)
    max_tokens: Optional[int] = None
    presence_penalty: float = Field(ge=-2.0, le=2.0, default=0.0)
    frequency_penalty: float = Field(ge=-2.0, le=2.0, default=0.0)

class HyperparametersConfig(BaseModel):
    default: RoleParams
    planner: RoleParams
    creative: RoleParams
    seed: int

class TimeoutPolicy(BaseModel):
    short: int
    medium: int
    long: int

class RetryPolicy(BaseModel):
    max_attempts: int
    initial_backoff: float
    max_backoff: float
    backoff_factor: float

class CircuitBreakerConfig(BaseModel):
    consecutive_failures_threshold: int
    reset_timeout: int

class ReliabilityConfig(BaseModel):
    timeout_policy: TimeoutPolicy
    retry_policy: RetryPolicy
    circuit_breaker: CircuitBreakerConfig

class CapabilitiesConfig(BaseModel):
    rag_enabled: bool
    web_search_enabled: bool
    shell_access_enabled: bool
    vpn_control_enabled: bool
    vision_enabled: bool

class ResourceControlConfig(BaseModel):
    monthly_budget_usd: float
    daily_token_limit: int
    max_parallel_tasks: int
    token_budget_per_session: int
    cost_tracking_enabled: bool

class SessionGovernanceConfig(BaseModel):
    max_turns_per_session: int
    session_ttl_seconds: int
    persist_on_shutdown: bool
    idle_shutdown_timeout: int

class GovernanceConfig(BaseModel):
    license: str
    data_retention_policy: str
    pii_redaction: bool
    audit_logging: bool
    compliance_standards: List[str]
    legal_disclaimer: str

class SecurityConfig(BaseModel):
    isolation_mode_default: bool
    integrity_check_interval: int
    allowed_domains: List[str]
    encryption_standard: str
    honeypot_enabled: bool

class ObservabilityConfig(BaseModel):
    logging_level: str
    telemetry_enabled: bool
    trace_sample_rate: float = Field(ge=0.0, le=1.0)
    performance_monitoring: bool

class AgentConfig(BaseModel):
    runtime: RuntimeConfig
    identity: IdentityConfig
    prompts: PromptsConfig
    models: ModelsConfig
    embeddings: EmbeddingsConfig
    hyperparameters: HyperparametersConfig
    reliability: ReliabilityConfig
    capabilities: CapabilitiesConfig
    resource_control: ResourceControlConfig
    session_governance: SessionGovernanceConfig
    governance: GovernanceConfig
    security: SecurityConfig
    observability: ObservabilityConfig

class ConfigurationManager:
    _instance: Optional['ConfigurationManager'] = None
    config: AgentConfig

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(cls)
            cls._instance.load_config()
        return cls._instance

    def load_config(self, path: str = "governance/agent_manifest.yaml"):
        try:
            from myth_utils.paths import get_resource_path
            resolved_path = get_resource_path(path)
            
            if not os.path.exists(resolved_path):
                logger.error(f"❌ Configuration file not found at {resolved_path}")
                raise FileNotFoundError(f"Config file {resolved_path} missing.")
            
            with open(resolved_path, "r") as f:
                raw_data = yaml.safe_load(f)
            
            # Environment variable overrides
            self._apply_env_overrides(raw_data)
            
            self.config = AgentConfig(**raw_data)
            logger.info(f"✅ Peak Industrial Configuration Loaded: {self.config.identity.name} v{self.config.identity.version} [{self.config.runtime.environment}]")
            
            if self.config.observability.logging_level:
                level = getattr(logging, self.config.observability.logging_level.upper(), logging.INFO)
                logging.getLogger().setLevel(level)
                
        except Exception as e:
            logger.error(f"❌ Failed to load configuration: {e}")
            raise

    def _apply_env_overrides(self, data: Dict[str, Any]):
        def walk_and_override(d: Dict, prefix: str):
            for k, v in d.items():
                env_key = f"CFG_{prefix}{k.upper()}"
                if isinstance(v, dict):
                    walk_and_override(v, f"{prefix}{k.upper()}_")
                elif os.getenv(env_key):
                    new_val = os.getenv(env_key)
                    if isinstance(v, bool):
                        d[k] = new_val.lower() in ("true", "1", "yes")
                    elif isinstance(v, (int, float)):
                        d[k] = type(v)(new_val)
                    elif isinstance(v, list):
                         d[k] = new_val.split(",")
                    else:
                        d[k] = new_val
                    logger.info(f"🔧 Environment override detected: {env_key}={d[k]}")

        walk_and_override(data, "")

# Global instance
config_manager = ConfigurationManager()
agent_config = config_manager.config
