"""
Validações reutilizáveis para o sistema SOAR
"""
import ipaddress
from enum import Enum
from typing import Optional
from pydantic import validator, ValidationError as PydanticValidationError

from config import SEVERITY_LEVELS, EVENT_TYPES
from exceptions import IPValidationError, EventValidationError, ValidationError


class Severity(str, Enum):
    """Níveis de severidade permitidos"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Tipos de eventos permitidos"""
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    MALWARE_DETECTED = "malware_detected"
    RANSOMWARE_DETECTED = "ransomware_detected"
    SUSPICIOUS_CONNECTION = "suspicious_connection"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DDOS_ATTACK = "ddos_attack"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    BRUTE_FORCE_ATTACK = "brute_force_attack"


def validate_ip(ip: str) -> str:
    """
    Valida um endereço IP usando a biblioteca ipaddress
    
    Args:
        ip: Endereço IP a ser validado
    
    Returns:
        IP validado como string
    
    Raises:
        IPValidationError: Se o IP for inválido
    """
    if not ip or not isinstance(ip, str):
        raise IPValidationError("IP não pode ser vazio", {"ip": ip})
    
    try:
        # Valida e normaliza o IP
        ip_obj = ipaddress.ip_address(ip.strip())
        return str(ip_obj)
    except ValueError as e:
        raise IPValidationError(
            f"Endereço IP inválido: {ip}",
            {"ip": ip, "error": str(e)}
        )


def validate_severity(severity: str) -> str:
    """
    Valida o nível de severidade
    
    Args:
        severity: Nível de severidade a ser validado
    
    Returns:
        Severidade validada (em lowercase)
    
    Raises:
        ValidationError: Se a severidade for inválida
    """
    if not severity:
        raise ValidationError("Severidade não pode ser vazia")
    
    severity_lower = severity.lower().strip()
    
    if severity_lower not in SEVERITY_LEVELS:
        raise ValidationError(
            f"Severidade inválida: {severity}. Valores permitidos: {', '.join(SEVERITY_LEVELS)}",
            {"severity": severity, "allowed": SEVERITY_LEVELS}
        )
    
    return severity_lower


def validate_event_type(event_type: str) -> str:
    """
    Valida o tipo de evento
    
    Args:
        event_type: Tipo de evento a ser validado
    
    Returns:
        Tipo de evento validado (em lowercase)
    
    Raises:
        EventValidationError: Se o tipo de evento for inválido
    """
    if not event_type:
        raise EventValidationError("Tipo de evento não pode ser vazio")
    
    event_type_lower = event_type.lower().strip()
    
    if event_type_lower not in EVENT_TYPES:
        raise EventValidationError(
            f"Tipo de evento inválido: {event_type}. Valores permitidos: {', '.join(EVENT_TYPES)}",
            {"event_type": event_type, "allowed": EVENT_TYPES}
        )
    
    return event_type_lower


def validate_ip_optional(ip: Optional[str]) -> Optional[str]:
    """
    Valida um IP opcional (pode ser None)
    
    Args:
        ip: Endereço IP opcional
    
    Returns:
        IP validado ou None
    """
    if ip is None or ip == "":
        return None
    return validate_ip(ip)


def is_private_ip(ip: str) -> bool:
    """
    Verifica se um IP é privado (RFC 1918)
    
    Args:
        ip: Endereço IP
    
    Returns:
        True se o IP for privado
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    """
    Verifica se um IP é reservado (loopback, multicast, etc)
    
    Args:
        ip: Endereço IP
    
    Returns:
        True se o IP for reservado
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved
    except ValueError:
        return False

