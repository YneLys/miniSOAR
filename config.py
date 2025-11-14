"""
Configurações do Sistema SOAR
Usa pydantic_settings para gerenciamento de configurações com suporte a variáveis de ambiente
"""
from typing import Dict, List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações da aplicação com validação"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    # API
    API_TITLE: str = Field(default="Mini SOAR System", description="Título da API")
    API_VERSION: str = Field(default="1.0.0", description="Versão da API")
    API_HOST: str = Field(default="0.0.0.0", description="Host da API")
    API_PORT: int = Field(default=8000, ge=1, le=65535, description="Porta da API")
    
    # Database
    DB_PATH: str = Field(default="soar_database.db", description="Caminho do banco de dados SQLite")
    
    # Automação
    FAILED_LOGIN_THRESHOLD: int = Field(
        default=5,
        ge=1,
        description="Número de tentativas de login falhadas antes de bloquear"
    )
    FAILED_LOGIN_WINDOW_MINUTES: int = Field(
        default=5,
        ge=1,
        description="Janela de tempo em minutos para contagem de tentativas"
    )
    
    # Threat Intelligence
    ENABLE_THREAT_INTEL: bool = Field(default=True, description="Habilitar verificação de threat intelligence")
    THREAT_INTEL_CACHE_HOURS: int = Field(default=24, ge=1, description="Horas de cache para threat intel")
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Nível de logging")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Formato de log"
    )
    LOG_FILE: Optional[str] = Field(default=None, description="Arquivo de log (opcional)")
    LOG_JSON: bool = Field(default=False, description="Usar formato JSON para logs")
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = Field(default=False, description="Habilitar rate limiting")
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=1, description="Requisições por minuto permitidas")
    
    # Playbooks
    PLAYBOOKS_DIR: str = Field(default="playbooks", description="Diretório de playbooks")
    
    # Retry Configuration
    RETRY_MAX_ATTEMPTS: int = Field(default=3, ge=1, description="Número máximo de tentativas para retry")
    RETRY_DELAY_SECONDS: float = Field(default=1.0, ge=0.1, description="Delay entre tentativas em segundos")
    
    # Circuit Breaker
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(
        default=5,
        ge=1,
        description="Número de falhas antes de abrir circuit breaker"
    )
    CIRCUIT_BREAKER_TIMEOUT_SECONDS: int = Field(
        default=60,
        ge=1,
        description="Timeout do circuit breaker em segundos"
    )
    
    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Valida o nível de log"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"LOG_LEVEL deve ser um de: {', '.join(valid_levels)}")
        return v.upper()
    
    @field_validator("API_PORT")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Valida a porta da API"""
        if not (1 <= v <= 65535):
            raise ValueError("API_PORT deve estar entre 1 e 65535")
        return v

# Instância global de configurações
try:
    settings = Settings()
except Exception as e:
    # Fallback para configurações padrão em caso de erro
    import logging
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.warning(f"Erro ao carregar configurações, usando padrões: {e}")
    settings = Settings()

# Configurações de severidade
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

# Tipos de eventos suportados
EVENT_TYPES = [
    "failed_login",
    "successful_login",
    "malware_detected",
    "ransomware_detected",
    "suspicious_connection",
    "port_scan",
    "data_exfiltration",
    "privilege_escalation",
    "unauthorized_access",
    "ddos_attack",
    "sql_injection",
    "xss_attack",
    "brute_force_attack"
]

# Configurações de alertas (mantidas como constantes para compatibilidade)
ALERT_CHANNELS: Dict[str, List[str]] = {
    "low": ["slack"],
    "medium": ["email", "slack"],
    "high": ["email", "slack"],
    "critical": ["email", "slack", "sms"]
}

EMAIL_RECIPIENTS: Dict[str, List[str]] = {
    "low": ["soc@company.com"],
    "medium": ["soc@company.com", "security-team@company.com"],
    "high": ["soc@company.com", "security-team@company.com", "manager@company.com"],
    "critical": ["soc@company.com", "security-team@company.com", "manager@company.com", "ciso@company.com"]
}

SLACK_CHANNELS: Dict[str, List[str]] = {
    "low": ["#security-alerts"],
    "medium": ["#security-alerts"],
    "high": ["#security-alerts", "#security-urgent"],
    "critical": ["#security-alerts", "#security-urgent", "#incident-response"]
}

SMS_EMERGENCY_CONTACTS: List[str] = [
    "+55-11-99999-1111",  # SOC Manager
    "+55-11-99999-2222"   # CISO
]

# Configurações de firewall (simulado)
FIREWALL_CONFIG = {
    "vendor": "simulated",
    "api_endpoint": "https://firewall.company.local/api",
    "default_action": "drop",
    "log_enabled": True
}

# Configurações de SIEM (simulado)
SIEM_CONFIG = {
    "vendor": "simulated",
    "log_sources": [
        "firewall",
        "ids/ips",
        "antivirus",
        "web_proxy",
        "vpn",
        "authentication_servers"
    ]
}

# Métricas e SLA
SLA_CONFIG = {
    "critical": {
        "response_time_minutes": 15,
        "escalation_time_minutes": 30
    },
    "high": {
        "response_time_minutes": 60,
        "escalation_time_minutes": 120
    },
    "medium": {
        "response_time_minutes": 240,
        "escalation_time_minutes": 480
    },
    "low": {
        "response_time_minutes": 1440,
        "escalation_time_minutes": 2880
    }
}