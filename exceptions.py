"""
Exceções customizadas do sistema SOAR
"""
from typing import Optional


class SOARException(Exception):
    """Exceção base para todas as exceções do sistema SOAR"""
    
    def __init__(self, message: str, details: Optional[dict] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class DatabaseError(SOARException):
    """Erro relacionado a operações do banco de dados"""
    pass


class ValidationError(SOARException):
    """Erro de validação de dados"""
    pass


class IPValidationError(ValidationError):
    """Erro na validação de endereço IP"""
    pass


class EventValidationError(ValidationError):
    """Erro na validação de evento de segurança"""
    pass


class PlaybookError(SOARException):
    """Erro na execução de um playbook"""
    pass


class BlockIPError(PlaybookError):
    """Erro ao bloquear IP"""
    pass


class AlertError(PlaybookError):
    """Erro ao enviar alerta"""
    pass


class ThreatIntelError(PlaybookError):
    """Erro na verificação de threat intelligence"""
    pass


class ConfigurationError(SOARException):
    """Erro de configuração do sistema"""
    pass


class RateLimitError(SOARException):
    """Erro de rate limiting - muitas requisições"""
    pass


class CircuitBreakerError(SOARException):
    """Erro quando circuit breaker está aberto"""
    pass

