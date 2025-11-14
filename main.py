from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import sqlite3
import json
import os
from pathlib import Path

# Importar playbooks
from playbooks.block_ip import block_ip_playbook
from playbooks.alert_manager import send_alert_playbook
from playbooks.threat_intel import check_threat_intel

app = FastAPI(title="Mini SOAR System", version="1.0.0")

# Configuração do banco de dados
DB_PATH = "soar_database.db"

# Modelos Pydantic
class SecurityEvent(BaseModel):
    event_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    severity: str  # low, medium, high, critical
    description: str
    timestamp: Optional[str] = None

class BlockedIP(BaseModel):
    ip: str
    reason: str

class IncidentResponse(BaseModel):
    incident_id: int
    status: str
    actions_taken: List[str]
    timestamp: str

# Inicializar banco de dados
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Tabela de eventos
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_type TEXT,
                  source_ip TEXT,
                  destination_ip TEXT,
                  username TEXT,
                  severity TEXT,
                  description TEXT,
                  timestamp TEXT,
                  processed INTEGER DEFAULT 0)''')
    
    # Tabela de IPs bloqueados
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT UNIQUE,
                  reason TEXT,
                  blocked_at TEXT,
                  active INTEGER DEFAULT 1)''')
    
    # Tabela de incidentes
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_id INTEGER,
                  status TEXT,
                  actions_taken TEXT,
                  created_at TEXT,
                  resolved_at TEXT)''')
    
    # Tabela de alertas
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  incident_id INTEGER,
                  alert_type TEXT,
                  message TEXT,
                  sent_at TEXT)''')
    
    conn.commit()
    conn.close()

# Função para processar evento automaticamente
async def process_event_automation(event_id: int, event: SecurityEvent):
    """
    Motor de automação - decide quais playbooks executar baseado no evento
    """
    actions_taken = []
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Criar incidente
    incident_id = create_incident(event_id, "open")
    
    # Regra 1: Múltiplas falhas de login
    if event.event_type == "failed_login":
        c.execute("SELECT COUNT(*) FROM events WHERE source_ip = ? AND event_type = 'failed_login' AND datetime(timestamp) > datetime('now', '-5 minutes')", 
                  (event.source_ip,))
        count = c.fetchone()[0]
        
        if count >= 5:
            # Executar playbook de bloqueio
            result = await block_ip_playbook(event.source_ip, f"Multiple failed logins: {count} attempts")
            actions_taken.append(f"Blocked IP {event.source_ip}")
            
            # Enviar alerta crítico
            alert = await send_alert_playbook(
                incident_id,
                "critical",
                f"IP {event.source_ip} blocked due to {count} failed login attempts"
            )
            actions_taken.append("Critical alert sent")
    
    # Regra 2: IPs suspeitos via Threat Intel
    if event.severity in ["high", "critical"]:
        threat_data = await check_threat_intel(event.source_ip)
        if threat_data.get("is_malicious"):
            result = await block_ip_playbook(event.source_ip, "Known malicious IP from threat intelligence")
            actions_taken.append(f"Blocked malicious IP {event.source_ip}")
            
            alert = await send_alert_playbook(
                incident_id,
                "critical",
                f"Known threat actor IP detected: {event.source_ip}"
            )
            actions_taken.append("Threat intelligence alert sent")
    
    # Regra 3: Eventos críticos sempre geram alerta
    if event.severity == "critical":
        alert = await send_alert_playbook(
            incident_id,
            "critical",
            f"Critical event: {event.description}"
        )
        actions_taken.append("Critical event alert sent")
    
    # Atualizar incidente com ações tomadas
    update_incident(incident_id, actions_taken)
    
    # Marcar evento como processado
    c.execute("UPDATE events SET processed = 1 WHERE id = ?", (event_id,))
    conn.commit()
    conn.close()
    
    return {
        "incident_id": incident_id,
        "actions_taken": actions_taken
    }

def create_incident(event_id: int, status: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    
    c.execute("""INSERT INTO incidents (event_id, status, actions_taken, created_at)
                 VALUES (?, ?, ?, ?)""",
              (event_id, status, json.dumps([]), timestamp))
    
    incident_id = c.lastrowid
    conn.commit()
    conn.close()
    return incident_id

def update_incident(incident_id: int, actions: List[str]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("""UPDATE incidents 
                 SET actions_taken = ?, status = 'processed'
                 WHERE id = ?""",
              (json.dumps(actions), incident_id))
    
    conn.commit()
    conn.close()

# Endpoints da API

@app.on_event("startup")
async def startup():
    init_db()
    # Criar diretório de playbooks se não existir
    Path("playbooks").mkdir(exist_ok=True)
    print("🚀 Mini SOAR System iniciado!")

@app.get("/")
async def root():
    return {
        "message": "Mini SOAR System API",
        "version": "1.0.0",
        "endpoints": {
            "POST /events": "Receber eventos de segurança",
            "GET /events": "Listar eventos",
            "GET /incidents": "Listar incidentes",
            "GET /blocked-ips": "Listar IPs bloqueados",
            "POST /block-ip": "Bloquear IP manualmente",
            "GET /alerts": "Listar alertas",
            "GET /stats": "Estatísticas do sistema"
        }
    }

@app.post("/events", status_code=201)
async def receive_event(event: SecurityEvent, background_tasks: BackgroundTasks):
    """
    Endpoint para receber eventos de segurança (simulando SIEM)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    timestamp = event.timestamp or datetime.now().isoformat()
    
    c.execute("""INSERT INTO events 
                 (event_type, source_ip, destination_ip, username, severity, description, timestamp)
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              (event.event_type, event.source_ip, event.destination_ip, 
               event.username, event.severity, event.description, timestamp))
    
    event_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Processar automação em background
    background_tasks.add_task(process_event_automation, event_id, event)
    
    return {
        "status": "Event received",
        "event_id": event_id,
        "message": "Event is being processed by automation engine"
    }

@app.get("/events")
async def list_events(limit: int = 50):
    """Listar eventos recentes"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("""SELECT * FROM events 
                 ORDER BY timestamp DESC LIMIT ?""", (limit,))
    
    events = []
    for row in c.fetchall():
        events.append({
            "id": row[0],
            "event_type": row[1],
            "source_ip": row[2],
            "destination_ip": row[3],
            "username": row[4],
            "severity": row[5],
            "description": row[6],
            "timestamp": row[7],
            "processed": bool(row[8])
        })
    
    conn.close()
    return {"events": events, "count": len(events)}

@app.get("/incidents")
async def list_incidents(limit: int = 50):
    """Listar incidentes"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("""SELECT * FROM incidents 
                 ORDER BY created_at DESC LIMIT ?""", (limit,))
    
    incidents = []
    for row in c.fetchall():
        incidents.append({
            "id": row[0],
            "event_id": row[1],
            "status": row[2],
            "actions_taken": json.loads(row[3]) if row[3] else [],
            "created_at": row[4],
            "resolved_at": row[5]
        })
    
    conn.close()
    return {"incidents": incidents, "count": len(incidents)}

@app.get("/blocked-ips")
async def list_blocked_ips():
    """Listar IPs bloqueados"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT * FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC")
    
    blocked = []
    for row in c.fetchall():
        blocked.append({
            "id": row[0],
            "ip": row[1],
            "reason": row[2],
            "blocked_at": row[3]
        })
    
    conn.close()
    return {"blocked_ips": blocked, "count": len(blocked)}

@app.post("/block-ip")
async def manual_block_ip(data: BlockedIP):
    """Bloquear IP manualmente"""
    result = await block_ip_playbook(data.ip, data.reason)
    return result

@app.get("/alerts")
async def list_alerts(limit: int = 50):
    """Listar alertas enviados"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("""SELECT * FROM alerts 
                 ORDER BY sent_at DESC LIMIT ?""", (limit,))
    
    alerts = []
    for row in c.fetchall():
        alerts.append({
            "id": row[0],
            "incident_id": row[1],
            "alert_type": row[2],
            "message": row[3],
            "sent_at": row[4]
        })
    
    conn.close()
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/stats")
async def get_stats():
    """Estatísticas do sistema"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Total de eventos
    c.execute("SELECT COUNT(*) FROM events")
    total_events = c.fetchone()[0]
    
    # Eventos por severidade
    c.execute("""SELECT severity, COUNT(*) 
                 FROM events 
                 GROUP BY severity""")
    severity_stats = dict(c.fetchall())
    
    # IPs bloqueados ativos
    c.execute("SELECT COUNT(*) FROM blocked_ips WHERE active = 1")
    blocked_ips = c.fetchone()[0]
    
    # Incidentes
    c.execute("SELECT COUNT(*) FROM incidents")
    total_incidents = c.fetchone()[0]
    
    # Alertas enviados
    c.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = c.fetchone()[0]
    
    conn.close()
    
    return {
        "total_events": total_events,
        "severity_breakdown": severity_stats,
        "active_blocked_ips": blocked_ips,
        "total_incidents": total_incidents,
        "total_alerts": total_alerts
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)