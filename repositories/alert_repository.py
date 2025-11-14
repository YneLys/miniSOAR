"""
Repositório para operações com alertas
"""
from typing import List, Optional, Dict
from datetime import datetime

from database import db_manager
from logger import get_logger
from exceptions import DatabaseError

logger = get_logger(__name__)


class AlertRepository:
    """Repositório para gerenciamento de alertas"""
    
    def create(
        self,
        incident_id: int,
        alert_type: str,
        message: str,
        channel: Optional[str] = None,
        status: str = "sent"
    ) -> int:
        """Cria um novo alerta"""
        try:
            timestamp = datetime.now().isoformat()
            
            query = """INSERT INTO alerts (incident_id, alert_type, message, sent_at, channel, status)
                      VALUES (?, ?, ?, ?, ?, ?)"""
            
            params = (incident_id, alert_type, message, timestamp, channel, status)
            alert_id = db_manager.execute_insert(query, params)
            
            logger.info(f"Alerta criado: ID={alert_id}, incidente={incident_id}, tipo={alert_type}")
            return alert_id
            
        except Exception as e:
            logger.error(f"Erro ao criar alerta: {e}")
            raise DatabaseError(f"Erro ao criar alerta: {str(e)}")
    
    def get_by_id(self, alert_id: int) -> Optional[Dict]:
        """Obtém um alerta por ID"""
        try:
            query = "SELECT * FROM alerts WHERE id = ?"
            results = db_manager.execute_query(query, (alert_id,))
            return dict(results[0]) if results else None
        except Exception as e:
            logger.error(f"Erro ao buscar alerta {alert_id}: {e}")
            raise DatabaseError(f"Erro ao buscar alerta: {str(e)}")
    
    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        incident_id: Optional[int] = None,
        alert_type: Optional[str] = None
    ) -> List[Dict]:
        """Lista alertas com filtros opcionais"""
        try:
            conditions = []
            params = []
            
            if incident_id:
                conditions.append("incident_id = ?")
                params.append(incident_id)
            
            if alert_type:
                conditions.append("alert_type = ?")
                params.append(alert_type)
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            query = f"""SELECT * FROM alerts 
                       {where_clause}
                       ORDER BY sent_at DESC 
                       LIMIT ? OFFSET ?"""
            
            params.extend([limit, offset])
            results = db_manager.execute_query(query, tuple(params))
            
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Erro ao listar alertas: {e}")
            raise DatabaseError(f"Erro ao listar alertas: {str(e)}")
    
    def count(self) -> int:
        """Conta o total de alertas"""
        try:
            query = "SELECT COUNT(*) as count FROM alerts"
            results = db_manager.execute_query(query)
            return results[0]['count'] if results else 0
        except Exception as e:
            logger.error(f"Erro ao contar alertas: {e}")
            raise DatabaseError(f"Erro ao contar alertas: {str(e)}")

