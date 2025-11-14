"""
Playbook: Gerenciador de Alertas
Descrição: Envia alertas via diferentes canais (Email, Slack, SMS simulados)
"""
import sqlite3
from datetime import datetime
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = "soar_database.db"

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
        
        if channels is None:
            # Definir canais baseado na severidade
            if severity == "critical":
                channels = ["email", "slack", "sms"]
            elif severity == "high":
                channels = ["email", "slack"]
            else:
                channels = ["slack"]
        
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
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        c.execute("""INSERT INTO alerts (incident_id, alert_type, message, sent_at)
                     VALUES (?, ?, ?, ?)""",
                  (incident_id, severity, message, timestamp))
        
        alert_id = c.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Alerta {alert_id} enviado com sucesso!")
        
        return {
            "status": "success",
            "alert_id": alert_id,
            "severity": severity,
            "channels": results,
            "timestamp": timestamp
        }
        
    except Exception as e:
        logger.error(f"Erro ao enviar alerta: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

async def send_email_alert(message: str, severity: str) -> dict:
    """
    Simula envio de email
    Em produção: integração com SendGrid, Amazon SES, etc.
    """
    logger.info(f"Enviando email - Severity: {severity}")
    
    # Definir destinatários baseado na severidade
    recipients = {
        "low": ["soc@company.com"],
        "medium": ["soc@company.com", "security-team@company.com"],
        "high": ["soc@company.com", "security-team@company.com", "manager@company.com"],
        "critical": ["soc@company.com", "security-team@company.com", "manager@company.com", "ciso@company.com"]
    }
    
    email_data = {
        "to": recipients.get(severity, ["soc@company.com"]),
        "subject": f"[{severity.upper()}] Security Alert",
        "body": message,
        "timestamp": datetime.now().isoformat(),
        "sent": True
    }
    
    # Simular envio
    logger.info(f"Email enviado para: {', '.join(email_data['to'])}")
    
    return email_data

async def send_slack_alert(message: str, severity: str) -> dict:
    """
    Simula envio para Slack
    Em produção: usar slack_sdk ou webhooks
    """
    logger.info(f"Enviando mensagem Slack - Severity: {severity}")
    
    # Definir canais baseado na severidade
    channels = {
        "low": ["#security-alerts"],
        "medium": ["#security-alerts"],
        "high": ["#security-alerts", "#security-urgent"],
        "critical": ["#security-alerts", "#security-urgent", "#incident-response"]
    }
    
    # Emojis por severidade
    emoji_map = {
        "low": "ℹ️",
        "medium": "⚠️",
        "high": "🚨",
        "critical": "🔴"
    }
    
    slack_message = {
        "channels": channels.get(severity, ["#security-alerts"]),
        "text": f"{emoji_map.get(severity, '🔔')} *[{severity.upper()}]* {message}",
        "username": "SOAR Bot",
        "icon_emoji": ":shield:",
        "timestamp": datetime.now().isoformat(),
        "sent": True
    }
    
    logger.info(f"Slack enviado para: {', '.join(slack_message['channels'])}")
    
    return slack_message

async def send_sms_alert(message: str, severity: str) -> dict:
    """
    Simula envio de SMS
    Em produção: integração com Twilio, AWS SNS, etc.
    """
    logger.info(f"Enviando SMS - Severity: {severity}")
    
    # SMS apenas para critical
    if severity != "critical":
        return {
            "sent": False,
            "reason": "SMS only for critical alerts"
        }
    
    # Números de emergência (simulados)
    emergency_contacts = [
        "+55-11-99999-1111",  # SOC Manager
        "+55-11-99999-2222"   # CISO
    ]
    
    sms_data = {
        "to": emergency_contacts,
        "message": f"[CRITICAL ALERT] {message[:160]}",  # SMS limit
        "timestamp": datetime.now().isoformat(),
        "sent": True
    }
    
    logger.info(f"SMS enviado para: {', '.join(sms_data['to'])}")
    
    return sms_data

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