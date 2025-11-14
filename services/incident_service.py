"""
Serviço para gerenciamento de incidentes
"""
from typing import Dict, List, Optional

from repositories import IncidentRepository, AlertRepository
from logger import get_logger
from exceptions import DatabaseError, ValidationError

logger = get_logger(__name__)


class IncidentService:
    """Serviço para lógica de negócio relacionada a incidentes"""
    
    def __init__(self):
        self.incident_repo = IncidentRepository()
        self.alert_repo = AlertRepository()
    
    def get_incident(self, incident_id: int) -> Optional[Dict]:
        """Obtém um incidente por ID"""
        try:
            return self.incident_repo.get_by_id(incident_id)
        except Exception as e:
            logger.error(f"Erro ao buscar incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao buscar incidente: {str(e)}")
    
    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None
    ) -> Dict:
        """Lista incidentes com filtros"""
        try:
            # Validar status se fornecido
            valid_statuses = ["open", "processed", "resolved", "closed"]
            if status and status not in valid_statuses:
                raise ValidationError(
                    f"Status inválido: {status}. Valores permitidos: {', '.join(valid_statuses)}"
                )
            
            incidents = self.incident_repo.list(
                limit=limit,
                offset=offset,
                status=status
            )
            
            return {
                "incidents": incidents,
                "count": len(incidents),
                "limit": limit,
                "offset": offset
            }
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Erro ao listar incidentes: {e}")
            raise DatabaseError(f"Erro ao listar incidentes: {str(e)}")
    
    def update_incident(
        self,
        incident_id: int,
        actions_taken: List[str],
        status: Optional[str] = None
    ) -> bool:
        """Atualiza um incidente com ações tomadas"""
        try:
            if not isinstance(actions_taken, list):
                raise ValidationError("actions_taken deve ser uma lista")
            
            return self.incident_repo.update(
                incident_id=incident_id,
                actions_taken=actions_taken,
                status=status
            )
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Erro ao atualizar incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao atualizar incidente: {str(e)}")
    
    def resolve_incident(self, incident_id: int) -> bool:
        """Resolve um incidente"""
        try:
            return self.incident_repo.resolve(incident_id)
        except Exception as e:
            logger.error(f"Erro ao resolver incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao resolver incidente: {str(e)}")
    
    def get_incident_alerts(self, incident_id: int) -> List[Dict]:
        """Obtém todos os alertas de um incidente"""
        try:
            return self.alert_repo.list(incident_id=incident_id)
        except Exception as e:
            logger.error(f"Erro ao buscar alertas do incidente {incident_id}: {e}")
            raise DatabaseError(f"Erro ao buscar alertas: {str(e)}")

