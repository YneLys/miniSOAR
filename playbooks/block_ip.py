"""
Playbook: Bloqueio de IP
Descrição: Bloqueia IPs maliciosos no firewall (simulado)
"""
import sqlite3
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = "soar_database.db"

async def block_ip_playbook(ip: str, reason: str) -> dict:
    """
    Playbook para bloquear IP suspeito
    
    Args:
        ip: Endereço IP a ser bloqueado
        reason: Motivo do bloqueio
    
    Returns:
        dict com status da operação
    """
    try:
        logger.info(f"🚫 Executando playbook: BLOCK IP - {ip}")
        
        # 1. Validar IP
        if not validate_ip(ip):
            return {
                "status": "error",
                "message": "Invalid IP address",
                "ip": ip
            }
        
        # 2. Verificar se já está bloqueado
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT id FROM blocked_ips WHERE ip = ? AND active = 1", (ip,))
        existing = c.fetchone()
        
        if existing:
            conn.close()
            return {
                "status": "already_blocked",
                "message": f"IP {ip} already blocked",
                "ip": ip
            }
        
        # 3. Adicionar ao banco de dados
        timestamp = datetime.now().isoformat()
        c.execute("""INSERT INTO blocked_ips (ip, reason, blocked_at, active)
                     VALUES (?, ?, ?, 1)""",
                  (ip, reason, timestamp))
        
        conn.commit()
        block_id = c.lastrowid
        conn.close()
        
        # 4. Simular bloqueio no firewall
        # Em produção, aqui você chamaria a API do firewall real
        firewall_result = simulate_firewall_block(ip)
        
        logger.info(f"✅ IP {ip} bloqueado com sucesso! Motivo: {reason}")
        
        return {
            "status": "success",
            "message": f"IP {ip} blocked successfully",
            "ip": ip,
            "reason": reason,
            "block_id": block_id,
            "firewall_response": firewall_result,
            "timestamp": timestamp
        }
        
    except Exception as e:
        logger.error(f"❌ Erro ao bloquear IP {ip}: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "ip": ip
        }

def validate_ip(ip: str) -> bool:
    """Valida formato de endereço IP"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

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
        logger.info(f"🔓 Executando playbook: UNBLOCK IP - {ip}")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ?", (ip,))
        
        if c.rowcount == 0:
            conn.close()
            return {
                "status": "not_found",
                "message": f"IP {ip} not found in blocked list",
                "ip": ip
            }
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ IP {ip} desbloqueado com sucesso!")
        
        return {
            "status": "success",
            "message": f"IP {ip} unblocked successfully",
            "ip": ip
        }
        
    except Exception as e:
        logger.error(f"❌ Erro ao desbloquear IP {ip}: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "ip": ip
        }