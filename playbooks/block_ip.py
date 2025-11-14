"""
Playbook: Bloqueio de IP
Descrição: Bloqueia IPs maliciosos no firewall (simulado)
"""
from datetime import datetime

from repositories import BlockedIPRepository
from validators import validate_ip
from logger import get_logger
from exceptions import BlockIPError, IPValidationError
from utils import retry_async, CircuitBreaker

logger = get_logger(__name__)

# Circuit breaker para operações de firewall
firewall_circuit_breaker = CircuitBreaker(
    failure_threshold=5,
    timeout_seconds=60,
    name="firewall_block"
)

async def block_ip_playbook(ip: str, reason: str) -> dict:
    """
    Playbook para bloquear IP suspeito com retry logic e circuit breaker
    
    Args:
        ip: Endereço IP a ser bloqueado
        reason: Motivo do bloqueio
    
    Returns:
        dict com status da operação
    """
    try:
        logger.info(f"Executando playbook: BLOCK IP - {ip}", extra={"ip": ip, "reason": reason})
        
        # 1. Validar IP
        try:
            ip = validate_ip(ip)
        except IPValidationError as e:
            logger.error(f"IP inválido: {ip}", extra={"ip": ip, "error": str(e)})
            raise BlockIPError(f"IP inválido: {ip}", {"ip": ip})
        
        # 2. Verificar se já está bloqueado
        blocked_repo = BlockedIPRepository()
        if blocked_repo.is_blocked(ip):
            logger.info(f"IP {ip} já está bloqueado", extra={"ip": ip})
            return {
                "status": "already_blocked",
                "message": f"IP {ip} already blocked",
                "ip": ip
            }
        
        # 3. Adicionar ao banco de dados
        try:
            block_id = blocked_repo.create(ip, reason)
        except Exception as e:
            logger.error(f"Erro ao criar bloqueio no banco: {e}", extra={"ip": ip}, exc_info=True)
            raise BlockIPError(f"Erro ao criar bloqueio: {str(e)}", {"ip": ip})
        
        # 4. Simular bloqueio no firewall com retry e circuit breaker
        async def block_firewall():
            return simulate_firewall_block(ip)
        
        try:
            firewall_result = await retry_async(
                block_firewall,
                max_attempts=3,
                delay=1.0,
                circuit_breaker=firewall_circuit_breaker
            )
        except Exception as e:
            logger.warning(
                f"Erro ao bloquear no firewall (continuando): {e}",
                extra={"ip": ip, "error": str(e)}
            )
            # Continuar mesmo se o firewall falhar - o IP já está no banco
            firewall_result = {"status": "error", "message": str(e)}
        
        logger.info(f"IP {ip} bloqueado com sucesso", extra={"ip": ip, "block_id": block_id})
        
        return {
            "status": "success",
            "message": f"IP {ip} blocked successfully",
            "ip": ip,
            "reason": reason,
            "block_id": block_id,
            "firewall_response": firewall_result,
            "timestamp": datetime.now().isoformat()
        }
        
    except BlockIPError:
        raise
    except Exception as e:
        logger.error(f"Erro inesperado ao bloquear IP {ip}: {e}", extra={"ip": ip}, exc_info=True)
        raise BlockIPError(f"Erro ao bloquear IP: {str(e)}", {"ip": ip})

def simulate_firewall_block(ip: str) -> dict:
    """
    Simula bloqueio no firewall
    Em produção, isso seria uma chamada para API do firewall real
    (Palo Alto, Fortinet, etc.)
    """
    # Simular diferentes tipos de bloqueio
    return {
        "firewall_rule_id": f"FW-BLOCK-{hash(ip) % 10000}",
        "action": "drop",
        "direction": "inbound",
        "protocol": "any",
        "source": ip,
        "destination": "any",
        "status": "active",
        "log_enabled": True
    }

async def unblock_ip_playbook(ip: str) -> dict:
    """
    Playbook para desbloquear IP
    """
    try:
        logger.info(f"Executando playbook: UNBLOCK IP - {ip}", extra={"ip": ip})
        
        # Validar IP
        try:
            ip = validate_ip(ip)
        except IPValidationError as e:
            raise BlockIPError(f"IP inválido: {ip}", {"ip": ip})
        
        # Desbloquear
        blocked_repo = BlockedIPRepository()
        success = blocked_repo.unblock(ip)
        
        if not success:
            return {
                "status": "not_found",
                "message": f"IP {ip} not found in blocked list",
                "ip": ip
            }
        
        logger.info(f"IP {ip} desbloqueado com sucesso", extra={"ip": ip})
        
        return {
            "status": "success",
            "message": f"IP {ip} unblocked successfully",
            "ip": ip
        }
        
    except BlockIPError:
        raise
    except Exception as e:
        logger.error(f"Erro ao desbloquear IP {ip}: {e}", extra={"ip": ip}, exc_info=True)
        raise BlockIPError(f"Erro ao desbloquear IP: {str(e)}", {"ip": ip})