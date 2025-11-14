"""
Repositório para operações com incidentes
"""
from typing import List, Optional, Dict
from datetime import datetime
import json

from database import db_manager
from logger import get_logger
from exceptions import DatabaseError

logger = get_logger(__name__)


class IncidentRepository:
    """Repositório para gerenciamento de incidentes"""
    
    def create(
        self,
        event_id: int,
        status: str = "open"
    ) -> int:
        """Cria um novo incidente"""
        try:
            timestamp = datetime.now().isoformat()
            
            query = """INSERT INTO incidents (event_id, status, actions_taken, created_at)
                      VALUES (?, ?, ?, ?)"""
            
            params = (event_id, status, json.dumps([]), timestamp)
            incident_id = db_manager.execute_insert(query, params)
            
            logger.info(f"Incidente criado: ID={incident_id}, evento={event_id}")
            return incident_id
            
        except Exception as e:
            logger.error(f"Erro ao criar incidente: {e}")
            raise DatabaseError(f"Erro ao criar incidente: {str(e)}")
    
    def get_by_id(self, incident_id: int) -> Optional[Dict]:
        """Obtém um incidente por ID"""
        try:
            query = "SELECT * FROM incidents WHERE id = ?"
            results = db_manager.execute_query(query, (incident_id,))
            
            if not results:
                return None
            
            incident = dict(results[0])
            # Parse actions_taken JSON
            if incident.get('actions_taken'):
                try:
                    incident['actions_taken'] = json.loads(incident['actions_taken'])
                except (json.JSONDecodeError, TypeError):
                    incident['actions_taken'] = []
            else:
                incident['actions_taken'] = []
            
            return incident
            
        except Exception as e:
            logger.error(f"Erro ao buscar incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao buscar incidente: {str(e)}")
    
    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Dict]:
        """Lista incidentes com filtros opcionais"""
        try:
            conditions = []
            params = []
            
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            query = f"""SELECT * FROM incidents 
                       {where_clause}
                       ORDER BY created_at DESC 
                       LIMIT ? OFFSET ?"""
            
            params.extend([limit, offset])
            results = db_manager.execute_query(query, tuple(params))
            
            # Processar resultados
            incidents = []
            for row in results:
                incident = dict(row)
                # Parse actions_taken
                if incident.get('actions_taken'):
                    try:
                        incident['actions_taken'] = json.loads(incident['actions_taken'])
                    except (json.JSONDecodeError, TypeError):
                        incident['actions_taken'] = []
                else:
                    incident['actions_taken'] = []
                
                incidents.append(incident)
            
            return incidents
            
        except Exception as e:
            logger.error(f"Erro ao listar incidentes: {e}")
            raise DatabaseError(f"Erro ao listar incidentes: {str(e)}")
    
    def update(
        self,
        incident_id: int,
        actions_taken: List[str],
        status: Optional[str] = None
    ) -> bool:
        """Atualiza um incidente"""
        try:
            if status:
                query = """UPDATE incidents 
                          SET actions_taken = ?, status = ?
                          WHERE id = ?"""
                params = (json.dumps(actions_taken), status, incident_id)
            else:
                query = """UPDATE incidents 
                          SET actions_taken = ?
                          WHERE id = ?"""
                params = (json.dumps(actions_taken), incident_id)
            
            rows_affected = db_manager.execute_update(query, params)
            return rows_affected > 0
            
        except Exception as e:
            logger.error(f"Erro ao atualizar incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao atualizar incidente: {str(e)}")
    
    def resolve(self, incident_id: int) -> bool:
        """Resolve um incidente"""
        try:
            resolved_at = datetime.now().isoformat()
            query = """UPDATE incidents 
                      SET status = 'resolved', resolved_at = ?
                      WHERE id = ?"""
            
            rows_affected = db_manager.execute_update(query, (resolved_at, incident_id))
            return rows_affected > 0
            
        except Exception as e:
            logger.error(f"Erro ao resolver incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao resolver incidente: {str(e)}")
    
    def count(self) -> int:
        """Conta o total de incidentes"""
        try:
            query = "SELECT COUNT(*) as count FROM incidents"
            results = db_manager.execute_query(query)
            return results[0]['count'] if results else 0
        except Exception as e:
            logger.error(f"Erro ao contar incidentes: {e}")
            raise DatabaseError(f"Erro ao contar incidentes: {str(e)}")

