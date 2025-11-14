"""
Serviço de automação - motor de regras e execução de playbooks
"""
from typing import Dict, List
import asyncio

from repositories import EventRepository, IncidentRepository
from services.event_service import EventService
from services.incident_service import IncidentService
from playbooks.block_ip import block_ip_playbook
from playbooks.alert_manager import send_alert_playbook
from playbooks.threat_intel import check_threat_intel
from config import settings
from logger import get_logger
from exceptions import PlaybookError, DatabaseError

logger = get_logger(__name__)


class AutomationService:
    """Serviço para automação de resposta a incidentes"""
    
    def __init__(self):
        self.event_repo = EventRepository()
        self.incident_repo = IncidentRepository()
        self.event_service = EventService()
        self.incident_service = IncidentService()
    
    async def process_event(self, event_id: int, event_data: Dict) -> Dict:
        """
        Processa um evento através do motor de automação
        Executa regras e playbooks conforme necessário
        """
        try:
            logger.info(
                f"Processando evento {event_id}",
                extra={"event_id": event_id, "event_type": event_data.get("event_type")}
            )
            
            # Obter incidente associado
            incident = self.incident_repo.get_by_id(
                self.incident_repo.create(event_id, "open")
            )
            
            if not incident:
                # Criar incidente se não existir
                incident_id = self.incident_repo.create(event_id, "open")
            else:
                incident_id = incident["id"]
            
            actions_taken = []
            
            # Regra 1: Múltiplas falhas de login
            if event_data.get("event_type") == "failed_login":
                source_ip = event_data.get("source_ip")
                if source_ip:
                    count = self.event_repo.count_failed_logins(
                        source_ip,
                        settings.FAILED_LOGIN_WINDOW_MINUTES
                    )
                    
                    if count >= settings.FAILED_LOGIN_THRESHOLD:
                        try:
                            result = await block_ip_playbook(
                                source_ip,
                                f"Multiple failed logins: {count} attempts"
                            )
                            if result.get("status") == "success":
                                actions_taken.append(f"Blocked IP {source_ip}")
                            
                            # Enviar alerta crítico
                            alert = await send_alert_playbook(
                                incident_id,
                                "critical",
                                f"IP {source_ip} blocked due to {count} failed login attempts"
                            )
                            if alert.get("status") == "success":
                                actions_taken.append("Critical alert sent")
                                
                        except Exception as e:
                            logger.error(
                                f"Erro ao executar playbook de bloqueio: {e}",
                                extra={"event_id": event_id, "ip": source_ip}
                            )
                            actions_taken.append(f"Error blocking IP: {str(e)}")
            
            # Regra 2: IPs suspeitos via Threat Intel
            if event_data.get("severity") in ["high", "critical"] and settings.ENABLE_THREAT_INTEL:
                source_ip = event_data.get("source_ip")
                if source_ip:
                    try:
                        threat_data = await check_threat_intel(source_ip)
                        if threat_data.get("is_malicious"):
                            result = await block_ip_playbook(
                                source_ip,
                                "Known malicious IP from threat intelligence"
                            )
                            if result.get("status") == "success":
                                actions_taken.append(f"Blocked malicious IP {source_ip}")
                            
                            alert = await send_alert_playbook(
                                incident_id,
                                "critical",
                                f"Known threat actor IP detected: {source_ip}"
                            )
                            if alert.get("status") == "success":
                                actions_taken.append("Threat intelligence alert sent")
                                
                    except Exception as e:
                        logger.error(
                            f"Erro ao verificar threat intel: {e}",
                            extra={"event_id": event_id, "ip": source_ip}
                        )
            
            # Regra 3: Eventos críticos sempre geram alerta
            if event_data.get("severity") == "critical":
                try:
                    alert = await send_alert_playbook(
                        incident_id,
                        "critical",
                        f"Critical event: {event_data.get('description', 'No description')}"
                    )
                    if alert.get("status") == "success":
                        actions_taken.append("Critical event alert sent")
                except Exception as e:
                    logger.error(
                        f"Erro ao enviar alerta crítico: {e}",
                        extra={"event_id": event_id}
                    )
            
            # Atualizar incidente com ações tomadas
            self.incident_repo.update(
                incident_id=incident_id,
                actions_taken=actions_taken,
                status="processed"
            )
            
            # Marcar evento como processado
            self.event_repo.mark_as_processed(event_id)
            
            logger.info(
                f"Evento {event_id} processado com sucesso",
                extra={
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "actions_count": len(actions_taken)
                }
            )
            
            return {
                "incident_id": incident_id,
                "actions_taken": actions_taken,
                "status": "processed"
            }
            
        except Exception as e:
            logger.error(
                f"Erro ao processar evento {event_id}: {e}",
                extra={"event_id": event_id},
                exc_info=True
            )
            # Não re-raise para não quebrar o background task
            return {
                "incident_id": None,
                "actions_taken": [],
                "status": "error",
                "error": str(e)
            }

