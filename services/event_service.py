"""
Serviço para gerenciamento de eventos de segurança
"""
from typing import Dict, List, Optional
from datetime import datetime

from repositories import EventRepository, IncidentRepository
from validators import validate_ip, validate_severity, validate_event_type, validate_ip_optional
from logger import get_logger
from exceptions import ValidationError, DatabaseError

logger = get_logger(__name__)


class EventService:
    """Serviço para lógica de negócio relacionada a eventos"""
    
    def __init__(self):
        self.event_repo = EventRepository()
        self.incident_repo = IncidentRepository()
    
    def create_event(
        self,
        event_type: str,
        source_ip: str,
        severity: str,
        description: str,
        destination_ip: Optional[str] = None,
        username: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> Dict:
        """
        Cria um novo evento de segurança com validação
        
        Returns:
            Dicionário com informações do evento criado
        """
        try:
            # Validações
            event_type = validate_event_type(event_type)
            source_ip = validate_ip(source_ip)
            severity = validate_severity(severity)
            destination_ip = validate_ip_optional(destination_ip)
            
            if not description or not description.strip():
                raise ValidationError("Descrição do evento não pode ser vazia")
            
            # Criar evento
            event_id = self.event_repo.create(
                event_type=event_type,
                source_ip=source_ip,
                destination_ip=destination_ip,
                username=username,
                severity=severity,
                description=description.strip(),
                timestamp=timestamp
            )
            
            # Criar incidente associado
            incident_id = self.incident_repo.create(event_id=event_id, status="open")
            
            logger.info(
                f"Evento criado: ID={event_id}, tipo={event_type}, severidade={severity}",
                extra={"event_id": event_id, "incident_id": incident_id}
            )
            
            return {
                "event_id": event_id,
                "incident_id": incident_id,
                "status": "received",
                "message": "Event received and incident created"
            }
            
        except ValidationError:
            raise
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(f"Erro inesperado ao criar evento: {e}", exc_info=True)
            raise DatabaseError(f"Erro ao criar evento: {str(e)}")
    
    def get_event(self, event_id: int) -> Optional[Dict]:
        """Obtém um evento por ID"""
        try:
            return self.event_repo.get_by_id(event_id)
        except Exception as e:
            logger.error(f"Erro ao buscar evento {event_id}: {e}")
            raise DatabaseError(f"Erro ao buscar evento: {str(e)}")
    
    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        processed: Optional[bool] = None,
        severity: Optional[str] = None
    ) -> Dict:
        """Lista eventos com filtros"""
        try:
            # Validar severidade se fornecida
            if severity:
                severity = validate_severity(severity)
            
            events = self.event_repo.list(
                limit=limit,
                offset=offset,
                processed=processed,
                severity=severity
            )
            
            return {
                "events": events,
                "count": len(events),
                "limit": limit,
                "offset": offset
            }
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Erro ao listar eventos: {e}")
            raise DatabaseError(f"Erro ao listar eventos: {str(e)}")
    
    def count_failed_logins(
        self,
        source_ip: str,
        window_minutes: int = 5
    ) -> int:
        """Conta tentativas de login falhadas para um IP"""
        try:
            validate_ip(source_ip)
            return self.event_repo.count_failed_logins(source_ip, window_minutes)
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Erro ao contar tentativas de login: {e}")
            raise DatabaseError(f"Erro ao contar tentativas de login: {str(e)}")
    
    def mark_as_processed(self, event_id: int) -> bool:
        """Marca um evento como processado"""
        try:
            return self.event_repo.mark_as_processed(event_id)
        except Exception as e:
            logger.error(f"Erro ao marcar evento como processado: {e}")
            raise DatabaseError(f"Erro ao marcar evento como processado: {str(e)}")
    
    def get_statistics(self) -> Dict:
        """Obtém estatísticas dos eventos"""
        try:
            return self.event_repo.get_statistics()
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            raise DatabaseError(f"Erro ao obter estatísticas: {str(e)}")

