"""
Repositório para operações com eventos de segurança
"""
from typing import List, Optional, Dict
from datetime import datetime
import json

from database import db_manager
from logger import get_logger
from exceptions import DatabaseError

logger = get_logger(__name__)


class EventRepository:
    """Repositório para gerenciamento de eventos de segurança"""
    
    def create(
        self,
        event_type: str,
        source_ip: str,
        severity: str,
        description: str,
        destination_ip: Optional[str] = None,
        username: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> int:
        """
        Cria um novo evento de segurança
        
        Returns:
            ID do evento criado
        """
        try:
            timestamp = timestamp or datetime.now().isoformat()
            
            query = """INSERT INTO events 
                      (event_type, source_ip, destination_ip, username, severity, description, timestamp)
                      VALUES (?, ?, ?, ?, ?, ?, ?)"""
            
            params = (event_type, source_ip, destination_ip, username, severity, description, timestamp)
            event_id = db_manager.execute_insert(query, params)
            
            logger.info(f"Evento criado: ID={event_id}, tipo={event_type}, IP={source_ip}")
            return event_id
            
        except Exception as e:
            logger.error(f"Erro ao criar evento: {e}")
            raise DatabaseError(f"Erro ao criar evento: {str(e)}")
    
    def get_by_id(self, event_id: int) -> Optional[Dict]:
        """Obtém um evento por ID"""
        try:
            query = "SELECT * FROM events WHERE id = ?"
            results = db_manager.execute_query(query, (event_id,))
            return results[0] if results else None
        except Exception as e:
            logger.error(f"Erro ao buscar evento {event_id}: {e}")
            raise DatabaseError(f"Erro ao buscar evento: {str(e)}")
    
    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        processed: Optional[bool] = None,
        severity: Optional[str] = None
    ) -> List[Dict]:
        """Lista eventos com filtros opcionais"""
        try:
            conditions = []
            params = []
            
            if processed is not None:
                conditions.append("processed = ?")
                params.append(1 if processed else 0)
            
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            query = f"""SELECT * FROM events 
                       {where_clause}
                       ORDER BY timestamp DESC 
                       LIMIT ? OFFSET ?"""
            
            params.extend([limit, offset])
            results = db_manager.execute_query(query, tuple(params))
            
            # Converter para dict e processar campos
            events = []
            for row in results:
                event = dict(row)
                event['processed'] = bool(event.get('processed', 0))
                events.append(event)
            
            return events
            
        except Exception as e:
            logger.error(f"Erro ao listar eventos: {e}")
            raise DatabaseError(f"Erro ao listar eventos: {str(e)}")
    
    def count_failed_logins(
        self,
        source_ip: str,
        window_minutes: int = 5
    ) -> int:
        """Conta tentativas de login falhadas em uma janela de tempo"""
        try:
            query = """SELECT COUNT(*) as count 
                       FROM events 
                       WHERE source_ip = ? 
                       AND event_type = 'failed_login' 
                       AND datetime(timestamp) > datetime('now', '-' || ? || ' minutes')"""
            
            results = db_manager.execute_query(query, (source_ip, window_minutes))
            return results[0]['count'] if results else 0
            
        except Exception as e:
            logger.error(f"Erro ao contar tentativas de login: {e}")
            raise DatabaseError(f"Erro ao contar tentativas de login: {str(e)}")
    
    def mark_as_processed(self, event_id: int) -> bool:
        """Marca um evento como processado"""
        try:
            query = "UPDATE events SET processed = 1 WHERE id = ?"
            rows_affected = db_manager.execute_update(query, (event_id,))
            return rows_affected > 0
        except Exception as e:
            logger.error(f"Erro ao marcar evento como processado: {e}")
            raise DatabaseError(f"Erro ao marcar evento como processado: {str(e)}")
    
    def get_statistics(self) -> Dict:
        """Obtém estatísticas dos eventos"""
        try:
            # Total de eventos
            total_query = "SELECT COUNT(*) as count FROM events"
            total_result = db_manager.execute_query(total_query)
            total_events = total_result[0]['count'] if total_result else 0
            
            # Eventos por severidade
            severity_query = """SELECT severity, COUNT(*) as count 
                               FROM events 
                               GROUP BY severity"""
            severity_results = db_manager.execute_query(severity_query)
            severity_breakdown = {row['severity']: row['count'] for row in severity_results}
            
            return {
                "total_events": total_events,
                "severity_breakdown": severity_breakdown
            }
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            raise DatabaseError(f"Erro ao obter estatísticas: {str(e)}")

