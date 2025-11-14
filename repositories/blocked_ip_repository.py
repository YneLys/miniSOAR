"""
Repositório para operações com IPs bloqueados
"""
from typing import List, Optional, Dict
from datetime import datetime

from database import db_manager
from logger import get_logger
from exceptions import DatabaseError

logger = get_logger(__name__)


class BlockedIPRepository:
    """Repositório para gerenciamento de IPs bloqueados"""
    
    def create(
        self,
        ip: str,
        reason: str
    ) -> int:
        """Cria um novo bloqueio de IP"""
        try:
            timestamp = datetime.now().isoformat()
            
            query = """INSERT INTO blocked_ips (ip, reason, blocked_at, active)
                      VALUES (?, ?, ?, 1)"""
            
            params = (ip, reason, timestamp)
            block_id = db_manager.execute_insert(query, params)
            
            logger.info(f"IP bloqueado: ID={block_id}, IP={ip}")
            return block_id
            
        except Exception as e:
            logger.error(f"Erro ao bloquear IP {ip}: {e}")
            raise DatabaseError(f"Erro ao bloquear IP: {str(e)}")
    
    def is_blocked(self, ip: str) -> bool:
        """Verifica se um IP está bloqueado"""
        try:
            query = "SELECT id FROM blocked_ips WHERE ip = ? AND active = 1"
            results = db_manager.execute_query(query, (ip,))
            return len(results) > 0
        except Exception as e:
            logger.error(f"Erro ao verificar bloqueio de IP {ip}: {e}")
            raise DatabaseError(f"Erro ao verificar bloqueio: {str(e)}")
    
    def get_by_ip(self, ip: str) -> Optional[Dict]:
        """Obtém informações de bloqueio de um IP"""
        try:
            query = "SELECT * FROM blocked_ips WHERE ip = ? AND active = 1 ORDER BY blocked_at DESC LIMIT 1"
            results = db_manager.execute_query(query, (ip,))
            return dict(results[0]) if results else None
        except Exception as e:
            logger.error(f"Erro ao buscar bloqueio de IP {ip}: {e}")
            raise DatabaseError(f"Erro ao buscar bloqueio: {str(e)}")
    
    def list(
        self,
        active_only: bool = True,
        limit: int = 100
    ) -> List[Dict]:
        """Lista IPs bloqueados"""
        try:
            if active_only:
                query = """SELECT * FROM blocked_ips 
                          WHERE active = 1 
                          ORDER BY blocked_at DESC 
                          LIMIT ?"""
                params = (limit,)
            else:
                query = """SELECT * FROM blocked_ips 
                          ORDER BY blocked_at DESC 
                          LIMIT ?"""
                params = (limit,)
            
            results = db_manager.execute_query(query, params)
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Erro ao listar IPs bloqueados: {e}")
            raise DatabaseError(f"Erro ao listar IPs bloqueados: {str(e)}")
    
    def unblock(self, ip: str) -> bool:
        """Desbloqueia um IP"""
        try:
            query = "UPDATE blocked_ips SET active = 0 WHERE ip = ? AND active = 1"
            rows_affected = db_manager.execute_update(query, (ip,))
            
            if rows_affected > 0:
                logger.info(f"IP desbloqueado: {ip}")
            
            return rows_affected > 0
            
        except Exception as e:
            logger.error(f"Erro ao desbloquear IP {ip}: {e}")
            raise DatabaseError(f"Erro ao desbloquear IP: {str(e)}")
    
    def count_active(self) -> int:
        """Conta IPs bloqueados ativos"""
        try:
            query = "SELECT COUNT(*) as count FROM blocked_ips WHERE active = 1"
            results = db_manager.execute_query(query)
            return results[0]['count'] if results else 0
        except Exception as e:
            logger.error(f"Erro ao contar IPs bloqueados: {e}")
            raise DatabaseError(f"Erro ao contar IPs bloqueados: {str(e)}")

