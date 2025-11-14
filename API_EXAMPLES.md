# 📡 Exemplos de Uso da API

## Testando a API

### 1. Verificar Status da API

```bash
curl http://localhost:8000/
```

**Response**:
```json
{
  "message": "Mini SOAR System API",
  "version": "1.0.0",
  "endpoints": {...}
}
```

## Enviando Eventos

### 2. Evento de Falha de Login

```bash
curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "failed_login",
    "source_ip": "192.168.1.100",
    "username": "admin",
    "severity": "medium",
    "description": "Failed authentication attempt"
  }'
```

### 3. Evento Crítico - Malware Detectado

```bash
curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "malware_detected",
    "source_ip": "10.0.0.50",
    "severity": "critical",
    "description": "Ransomware activity detected on endpoint"
  }'
```

### 4. Port Scan Detectado

```bash
curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "port_scan",
    "source_ip": "203.0.113.50",
    "destination_ip": "192.168.1.5",
    "severity": "medium",
    "description": "Port scan detected on multiple ports"
  }'
```

### 5. Conexão Suspeita

```bash
curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "suspicious_connection",
    "source_ip": "172.16.0.200",
    "destination_ip": "192.168.1.10",
    "severity": "high",
    "description": "Connection attempt from known malware C2 server"
  }'
```

## Consultando Dados

### 6. Listar Eventos (últimos 10)

```bash
curl "http://localhost:8000/events?limit=10"
```

### 7. Listar Todos os Incidentes

```bash
curl http://localhost:8000/incidents
```

### 8. Ver IPs Bloqueados

```bash
curl http://localhost:8000/blocked-ips
```

**Response esperado**:
```json
{
  "blocked_ips": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "reason": "Multiple failed logins: 5 attempts",
      "blocked_at": "2025-11-14T10:30:00.000000"
    }
  ],
  "count": 1
}
```

### 9. Ver Alertas Enviados

```bash
curl http://localhost:8000/alerts
```

### 10. Estatísticas do Sistema

```bash
curl http://localhost:8000/stats
```

**Response**:
```json
{
  "total_events": 25,
  "severity_breakdown": {
    "low": 5,
    "medium": 12,
    "high": 6,
    "critical": 2
  },
  "active_blocked_ips": 3,
  "total_incidents": 8,
  "total_alerts": 5
}
```

## Ações Manuais

### 11. Bloquear IP Manualmente

```bash
curl -X POST "http://localhost:8000/block-ip" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "198.51.100.25",
    "reason": "Manual block - Suspicious activity reported by analyst"
  }'
```

**Response**:
```json
{
  "status": "success",
  "message": "IP 198.51.100.25 blocked successfully",
  "ip": "198.51.100.25",
  "reason": "Manual block - Suspicious activity reported by analyst",
  "block_id": 4,
  "timestamp": "2025-11-14T11:00:00.000000"
}
```

## Cenários de Teste Completos

### Cenário 1: Simular Ataque de Força Bruta

```bash
#!/bin/bash
# Script para simular 6 tentativas de login

for i in {1..6}; do
  echo "Tentativa $i..."
  curl -X POST "http://localhost:8000/events" \
    -H "Content-Type: application/json" \
    -d "{
      \"event_type\": \"failed_login\",
      \"source_ip\": \"192.168.1.100\",
      \"username\": \"admin$i\",
      \"severity\": \"medium\",
      \"description\": \"Failed login attempt #$i\"
    }"
  sleep 1
done

echo "Verificando se IP foi bloqueado..."
sleep 3
curl http://localhost:8000/blocked-ips
```

### Cenário 2: Múltiplos Eventos Críticos

```bash
#!/bin/bash
# Eventos críticos simultâneos

curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "ransomware_detected",
    "source_ip": "10.0.0.50",
    "severity": "critical",
    "description": "Ransomware encryption activity detected"
  }'

curl -X POST "http://localhost:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "data_exfiltration",
    "source_ip": "10.0.0.50",
    "destination_ip": "185.0.0.100",
    "severity": "critical",
    "description": "Large data transfer to external IP"
  }'

echo "Verificando alertas gerados..."
sleep 2
curl http://localhost:8000/alerts
```

### Cenário 3: Scan de Rede

```bash
#!/bin/bash
# Simular port scan de um scanner

SCANNER_IP="203.0.113.50"

for port in 22 80 443 3389 8080 8443; do
  curl -X POST "http://localhost:8000/events" \
    -H "Content-Type: application/json" \
    -d "{
      \"event_type\": \"port_scan\",
      \"source_ip\": \"$SCANNER_IP\",
      \"destination_ip\": \"192.168.1.5\",
      \"severity\": \"medium\",
      \"description\": \"Port $port scan detected\"
    }"
  sleep 0.5
done
```

## Usando Python Requests

### Exemplo em Python

```python
import requests
import json

BASE_URL = "http://localhost:8000"

# 1. Enviar evento
def send_event(event_data):
    response = requests.post(
        f"{BASE_URL}/events",
        json=event_data
    )
    return response.json()

# 2. Verificar estatísticas
def get_stats():
    response = requests.get(f"{BASE_URL}/stats")
    return response.json()

# 3. Listar IPs bloqueados
def get_blocked_ips():
    response = requests.get(f"{BASE_URL}/blocked-ips")
    return response.json()

# Uso
if __name__ == "__main__":
    # Enviar evento de falha de login
    event = {
        "event_type": "failed_login",
        "source_ip": "192.168.1.100",
        "username": "admin",
        "severity": "medium",
        "description": "Failed login attempt"
    }
    
    result = send_event(event)
    print("Evento enviado:", result)
    
    # Ver estatísticas
    stats = get_stats()
    print("\nEstatísticas:", json.dumps(stats, indent=2))
```

## Testando com Postman

### Importar Collection

1. Abra Postman
2. Importe a seguinte collection:

```json
{
  "info": {
    "name": "Mini SOAR API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Send Failed Login Event",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"event_type\": \"failed_login\",\n  \"source_ip\": \"192.168.1.100\",\n  \"username\": \"admin\",\n  \"severity\": \"medium\",\n  \"description\": \"Failed login attempt\"\n}"
        },
        "url": {
          "raw": "http://localhost:8000/events",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8000",
          "path": ["events"]
        }
      }
    },
    {
      "name": "Get Statistics",
      "request": {
        "method": "GET",
        "url": {
          "raw": "http://localhost:8000/stats",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8000",
          "path": ["stats"]
        }
      }
    }
  ]
}
```

## Documentação Interativa

Acesse `http://localhost:8000/docs` para usar a interface Swagger UI:

- ✅ Testar todos os endpoints
- ✅ Ver schemas de request/response
- ✅ Executar requests diretamente do navegador
- ✅ Ver exemplos automáticos

## Monitoramento em Tempo Real

### Ver logs do container

```bash
# Se usando Docker
docker-compose logs -f soar-api

# Ver apenas últimas 100 linhas
docker-compose logs --tail=100 soar-api
```

### Ver logs da aplicação

```bash
# Se rodando localmente
tail -f /var/log/soar.log
```

## Troubleshooting

### API não responde

```bash
# Verificar se está rodando
curl http://localhost:8000/

# Verificar logs
docker-compose logs soar-api

# Reiniciar container
docker-compose restart soar-api
```

### Banco de dados corrompido

```bash
# Remover banco e reiniciar
rm soar_database.db
docker-compose restart soar-api
```

### Limpar todos os dados

```bash
# Parar containers
docker-compose down

# Remover volumes
docker-compose down -v

# Remover banco
rm soar_database.db

# Reiniciar
docker-compose up --build
```