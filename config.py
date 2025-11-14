"""
Configurações do Sistema SOAR
"""
from typing import Dict, List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Configurações da aplicação"""
    
    # API
    API_TITLE: str = "Mini SOAR System"
    API_VERSION: str = "1.0.0"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    
    # Database
    DB_PATH: str = "soar_database.db"
    
    # Automação
    FAILED_LOGIN_THRESHOLD: int = 5  # Número de tentativas antes de bloquear
    FAILED_LOGIN_WINDOW_MINUTES: int = 5  # Janela de tempo para contagem
    
    # Alertas
    ALERT_CHANNELS: Dict[str, List[str]] = {
        "low": ["slack"],
        "medium": ["email", "slack"],
        "high": ["email", "slack"],
        "critical": ["email", "slack", "sms"]
    }
    
    # Email (simulado)
    EMAIL_RECIPIENTS: Dict[str, List[str]] = {
        "low": ["soc@company.com"],
        "medium": ["soc@company.com", "security-team@company.com"],
        "high": ["soc@company.com", "security-team@company.com", "manager@company.com"],
        "critical": ["soc@company.com", "security-team@company.com", "manager@company.com", "ciso@company.com"]
    }
    
    # Slack (simulado)
    SLACK_CHANNELS: Dict[str, List[str]] = {
        "low": ["#security-alerts"],
        "medium": ["#security-alerts"],
        "high": ["#security-alerts", "#security-urgent"],
        "critical": ["#security-alerts", "#security-urgent", "#incident-response"]
    }
    
    # SMS (simulado)
    SMS_EMERGENCY_CONTACTS: List[str] = [
        "+55-11-99999-1111",  # SOC Manager
        "+55-11-99999-2222"   # CISO
    ]
    
    # Threat Intelligence
    ENABLE_THREAT_INTEL: bool = True
    THREAT_INTEL_CACHE_HOURS: int = 24
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Rate Limiting (para produção)
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Playbooks
    PLAYBOOKS_DIR: str = "playbooks"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Instância global de configurações
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