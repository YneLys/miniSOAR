# Mini SOAR System

Sistema de SOAR (Security Orchestration, Automation and Response) simulado para demonstrar automação de resposta a incidentes de segurança.

## Visão Geral

O Mini SOAR simula um sistema real de resposta automatizada a incidentes, incluindo:

- Recepção de eventos de segurança
- Análise automática com regras
- Execução de playbooks de resposta
- Integração com Threat Intelligence
- Sistema de alertas multi-canal
- Registro e auditoria

## Características

### Automação Completa

- Motor de regras que processa eventos automaticamente
- Playbooks automatizados sem intervenção manual
- Correlação de eventos e identificação de padrões
- Resposta em tempo real para eventos críticos

### Tipos de Resposta

- Bloqueio automático de IPs maliciosos
- Alertas via Email, Slack e SMS (simulados)
- Verificação em bases de Threat Intelligence
- Criação de tickets para análise

## Tecnologias

- Python 3.11+
- FastAPI
- SQLite
- Uvicorn
- Docker
- Pydantic

## Instalação

### Opção 1: Local

```bash
git clone <seu-repo>
cd mini-soar

python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

pip install -r requirements.txt

python main.py
```

### Opção 2: Docker

```bash
docker-compose up --build
```

API disponível em: http://localhost:8000

## Uso

### Executar Testes

```bash
python test_soar.py
```

### Documentação Interativa

Acesse: http://localhost:8000/docs

### Enviar Evento Manual

```bash
curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "failed_login",
    "source_ip": "192.168.1.100",
    "username": "admin",
    "severity": "medium",
    "description": "Failed login attempt"
  }'
```

## Arquitetura

```
mini-soar/
├── main.py
├── config.py
├── test_soar.py
├── playbooks/
│   ├── block_ip.py
│   ├── alert_manager.py
│   └── threat_intel.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Playbooks

### 1. Block IP (block_ip.py)

Bloqueia IPs maliciosos automaticamente.

```python
from playbooks.block_ip import block_ip_playbook

result = await block_ip_playbook(
    ip="192.168.1.100",
    reason="Multiple failed login attempts"
)
```

### 2. Alert Manager (alert_manager.py)

Envia alertas via múltiplos canais.

Níveis:
- low: Slack
- medium: Email + Slack
- high: Email + Slack + escalação
- critical: Todos + SMS

```python
from playbooks.alert_manager import send_alert_playbook

result = await send_alert_playbook(
    incident_id=1,
    severity="critical",
    message="Ransomware detected"
)
```

### 3. Threat Intelligence (threat_intel.py)

Verifica IPs contra bases de ameaças.

```python
from playbooks.threat_intel import check_threat_intel

result = await check_threat_intel(ip="192.168.1.100")
```

## API Endpoints

### POST /events
Recebe eventos de segurança

### GET /events
Lista eventos recentes

### GET /incidents
Lista incidentes processados

### GET /blocked-ips
Lista IPs bloqueados

### POST /block-ip
Bloqueia IP manualmente

### GET /alerts
Lista alertas enviados

### GET /stats
Estatísticas do sistema

## Regras de Automação

### Regra 1: Múltiplas Tentativas de Login
- Condição: 5+ falhas de login em 5 minutos
- Ação: Bloquear IP + Alerta crítico

### Regra 2: IPs em Threat Intelligence
- Condição: IP em base de ameaças
- Ação: Bloqueio imediato + Alerta

### Regra 3: Eventos Críticos
- Condição: Severidade "critical"
- Ação: Alerta em todos os canais

## Banco de Dados

### Tabelas SQLite

- events: Eventos de segurança
- incidents: Incidentes e ações
- blocked_ips: IPs bloqueados
- alerts: Histórico de alertas

## Segurança

Sistema de demonstração. Para produção:

- Implementar autenticação JWT
- Usar PostgreSQL
- Adicionar rate limiting
- Implementar HTTPS
- Integrar firewalls reais
- Conectar APIs reais de threat intel

## Exemplos de Uso

### Ataque de Força Bruta

```python
for i in range(6):
    requests.post("http://localhost:8000/events", json={
        "event_type": "failed_login",
        "source_ip": "192.168.1.100",
        "username": "admin",
        "severity": "medium",
        "description": f"Failed login #{i+1}"
    })
```

### Detecção de Malware

```python
requests.post("http://localhost:8000/events", json={
    "event_type": "malware_detected",
    "source_ip": "10.0.0.50",
    "severity": "critical",
    "description": "Ransomware detected"
})
```

## Contribuindo

Áreas para expansão:

- Mais playbooks
- Dashboard web
- Integração com SIEM real
- Machine Learning
- Workflow de aprovação

## Licença

Open source para fins educacionais.

## Autor

Demonstração de conceitos SOAR e automação de segurança.