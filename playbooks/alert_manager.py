"""
Playbook: Gerenciador de Alertas
Descrição: Envia alertas via diferentes canais (Email, Slack, SMS simulados)
"""
from datetime import datetime

from repositories import AlertRepository
from validators import validate_severity
from logger import get_logger
from exceptions import AlertError, ValidationError
from utils import retry_async, CircuitBreaker
from config import ALERT_CHANNELS, EMAIL_RECIPIENTS, SLACK_CHANNELS, SMS_EMERGENCY_CONTACTS

logger = get_logger(__name__)

# Circuit breakers por canal
email_circuit_breaker = CircuitBreaker(name="email_alerts", failure_threshold=5, timeout_seconds=60)
slack_circuit_breaker = CircuitBreaker(name="slack_alerts", failure_threshold=5, timeout_seconds=60)
sms_circuit_breaker = CircuitBreaker(name="sms_alerts", failure_threshold=3, timeout_seconds=120)

async def send_alert_playbook(incident_id: int, severity: str, message: str, channels: list = None) -> dict:
    """
    Playbook para envio de alertas
    
    Args:
        incident_id: ID do incidente relacionado
        severity: Nível de severidade (low, medium, high, critical)
        message: Mensagem do alerta
        channels: Lista de canais (email, slack, sms). Se None, usa todos.
    
    Returns:
        dict com status do envio
    """
    try:
        logger.info(f"Executando playbook: SEND ALERT - Severity: {severity}")
        
        # Validar severidade
        try:
            severity = validate_severity(severity)
        except ValidationError as e:
            raise AlertError(f"Severidade inválida: {str(e)}")
        
        if channels is None:
            channels = ALERT_CHANNELS.get(severity, ["slack"])
        
        results = {}
        
        # Enviar para cada canal
        for channel in channels:
            if channel == "email":
                results["email"] = await send_email_alert(message, severity)
            elif channel == "slack":
                results["slack"] = await send_slack_alert(message, severity)
            elif channel == "sms":
                results["sms"] = await send_sms_alert(message, severity)
        
        # Registrar alerta no banco
        try:
            alert_repo = AlertRepository()
            timestamp = datetime.now().isoformat()
            alert_id = alert_repo.create(
                incident_id=incident_id,
                alert_type=severity,
                message=message,
                channel=",".join(channels) if channels else None
            )
        except Exception as e:
            logger.error(f"Erro ao registrar alerta no banco: {e}", exc_info=True)
            # Continuar mesmo se falhar o registro
            alert_id = None
        
        logger.info(f"Alerta {alert_id} enviado com sucesso!")
        
        return {
            "status": "success",
            "alert_id": alert_id,
            "severity": severity,
            "channels": results,
            "timestamp": timestamp
        }
        
    except AlertError:
        raise
    except Exception as e:
        logger.error(f"Erro inesperado ao enviar alerta: {e}", exc_info=True)
        raise AlertError(f"Erro ao enviar alerta: {str(e)}")

async def send_email_alert(message: str, severity: str) -> dict:
    """
    Simula envio de email com retry logic
    Em produção: integração com SendGrid, Amazon SES, etc.
    """
    async def _send():
        logger.info(f"Enviando email - Severity: {severity}", extra={"severity": severity})
        recipients = EMAIL_RECIPIENTS.get(severity, ["soc@company.com"])
    
        email_data = {
            "to": recipients,
            "subject": f"[{severity.upper()}] Security Alert",
            "body": message,
            "timestamp": datetime.now().isoformat(),
            "sent": True
        }
        logger.info(f"Email enviado para: {', '.join(recipients)}")
        return email_data
    
    try:
        return await retry_async(_send, max_attempts=3, circuit_breaker=email_circuit_breaker)
    except Exception as e:
        logger.error(f"Erro ao enviar email: {e}", exc_info=True)
        raise AlertError(f"Erro ao enviar email: {str(e)}")

async def send_slack_alert(message: str, severity: str) -> dict:
    """
    Simula envio para Slack com retry logic
    Em produção: usar slack_sdk ou webhooks
    """
    async def _send():
        logger.info(f"Enviando mensagem Slack - Severity: {severity}", extra={"severity": severity})
        channels = SLACK_CHANNELS.get(severity, ["#security-alerts"])
    
        emoji_map = {
            "low": "ℹ️",
            "medium": "⚠️",
            "high": "🚨",
            "critical": "🔴"
        }
        
        slack_message = {
            "channels": channels,
            "text": f"{emoji_map.get(severity, '🔔')} *[{severity.upper()}]* {message}",
            "username": "SOAR Bot",
            "icon_emoji": ":shield:",
            "timestamp": datetime.now().isoformat(),
            "sent": True
        }
        logger.info(f"Slack enviado para: {', '.join(channels)}")
        return slack_message
    
    try:
        return await retry_async(_send, max_attempts=3, circuit_breaker=slack_circuit_breaker)
    except Exception as e:
        logger.error(f"Erro ao enviar Slack: {e}", exc_info=True)
        raise AlertError(f"Erro ao enviar Slack: {str(e)}")

async def send_sms_alert(message: str, severity: str) -> dict:
    """
    Simula envio de SMS com retry logic
    Em produção: integração com Twilio, AWS SNS, etc.
    """
    # SMS apenas para critical
    if severity != "critical":
        return {
            "sent": False,
            "reason": "SMS only for critical alerts"
        }
    
    async def _send():
        logger.info(f"Enviando SMS - Severity: {severity}", extra={"severity": severity})
        sms_data = {
            "to": SMS_EMERGENCY_CONTACTS,
            "message": f"[CRITICAL ALERT] {message[:160]}",  # SMS limit
            "timestamp": datetime.now().isoformat(),
            "sent": True
        }
        logger.info(f"SMS enviado para: {', '.join(SMS_EMERGENCY_CONTACTS)}")
        return sms_data
    
    try:
        return await retry_async(_send, max_attempts=2, circuit_breaker=sms_circuit_breaker)
    except Exception as e:
        logger.error(f"Erro ao enviar SMS: {e}", exc_info=True)
        raise AlertError(f"Erro ao enviar SMS: {str(e)}")

async def create_ticket_playbook(incident_id: int, title: str, description: str, priority: str) -> dict:
    """
    Playbook para criar ticket no sistema de ticketing
    Em produção: integração com Jira, ServiceNow, etc.
    """
    logger.info(f"Criando ticket para incidente {incident_id}")
    
    ticket_data = {
        "ticket_id": f"SEC-{incident_id:05d}",
        "title": title,
        "description": description,
        "priority": priority,
        "status": "open",
        "assigned_to": "SOC Team",
        "created_at": datetime.now().isoformat(),
        "sla_hours": 24 if priority in ["high", "critical"] else 72
    }
    
    logger.info(f"Ticket {ticket_data['ticket_id']} criado com sucesso!")
    
    return ticket_data