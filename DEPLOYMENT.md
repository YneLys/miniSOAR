# 🚀 Guia de Deployment

## Índice

1. [Deployment Local](#deployment-local)
2. [Deployment com Docker](#deployment-com-docker)
3. [Deployment em Produção](#deployment-em-produção)
4. [Monitoramento](#monitoramento)
5. [Backup e Recuperação](#backup-e-recuperação)
6. [Melhorias para Produção](#melhorias-para-produção)

## Deployment Local

### Requisitos

- Python 3.11 ou superior
- pip
- virtualenv (recomendado)

### Passo a Passo

```bash
# 1. Clone o repositório
git clone <seu-repo>
cd mini-soar

# 2. Crie ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# 3. Instale dependências
pip install -r requirements.txt

# 4. Execute a aplicação
python main.py

# A API estará disponível em http://localhost:8000
```

### Executar em Background (Linux/Mac)

```bash
# Usando nohup
nohup python main.py > soar.log 2>&1 &

# Verificar processo
ps aux | grep main.py

# Parar processo
kill <PID>
```

### Executar como Serviço (systemd)

Criar arquivo `/etc/systemd/system/soar.service`:

```ini
[Unit]
Description=Mini SOAR System
After=network.target

[Service]
Type=simple
User=soar
WorkingDirectory=/opt/mini-soar
Environment="PATH=/opt/mini-soar/venv/bin"
ExecStart=/opt/mini-soar/venv/bin/python main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Habilitar e iniciar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable soar
sudo systemctl start soar
sudo systemctl status soar
```

## Deployment com Docker

### Build Local

```bash
# Build da imagem
docker build -t mini-soar:latest .

# Executar container
docker run -d \
  --name mini-soar \
  -p 8000:8000 \
  -v $(pwd)/soar_database.db:/app/soar_database.db \
  mini-soar:latest

# Ver logs
docker logs -f mini-soar

# Parar container
docker stop mini-soar

# Remover container
docker rm mini-soar
```

### Docker Compose (Recomendado)

```bash
# Iniciar todos os serviços
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar serviços
docker-compose down

# Reconstruir após mudanças
docker-compose up -d --build

# Ver status
docker-compose ps
```

### Docker Compose com Múltiplos Serviços

Adicionar ao `docker-compose.yml`:

```yaml
version: '3.8'

services:
  soar-api:
    build: .
    container_name: mini-soar
    ports:
      - "8000:8000"
    volumes:
      - ./soar_database.db:/app/soar_database.db
      - ./playbooks:/app/playbooks
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
    networks:
      - soar-network

  # Adicionar PostgreSQL para produção
  postgres:
    image: postgres:15-alpine
    container_name: soar-db
    environment:
      - POSTGRES_USER=soar
      - POSTGRES_PASSWORD=soar_password
      - POSTGRES_DB=soar
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - soar-network
    restart: unless-stopped

  # Adicionar Redis para cache
  redis:
    image: redis:7-alpine
    container_name: soar-cache
    networks:
      - soar-network
    restart: unless-stopped

  # Nginx como reverse proxy
  nginx:
    image: nginx:alpine
    container_name: soar-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - soar-api
    networks:
      - soar-network
    restart: unless-stopped

networks:
  soar-network:
    driver: bridge

volumes:
  postgres-data:
```

## Deployment em Produção

### 1. Preparação

```bash
# Criar usuário dedicado
sudo useradd -r -s /bin/bash soar
sudo mkdir -p /opt/mini-soar
sudo chown soar:soar /opt/mini-soar

# Clonar código
cd /opt/mini-soar
git clone <repo> .

# Configurar ambiente
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Variáveis de Ambiente

Criar arquivo `.env`:

```bash
# API
API_HOST=0.0.0.0
API_PORT=8000

# Database
DB_PATH=/var/lib/mini-soar/soar_database.db

# Security
API_KEY=your-secret-api-key-here
JWT_SECRET=your-jwt-secret-here

# Logs
LOG_LEVEL=INFO
LOG_PATH=/var/log/mini-soar/

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=100
```

### 3. Nginx Configuration

Criar `/etc/nginx/sites-available/soar`:

```nginx
upstream soar_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name soar.company.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soar.company.com;

    ssl_certificate /etc/ssl/certs/soar.crt;
    ssl_certificate_key /etc/ssl/private/soar.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    client_max_body_size 10M;
    
    location / {
        proxy_pass http://soar_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://soar_backend/;
    }
}
```

Habilitar site:

```bash
sudo ln -s /etc/nginx/sites-available/soar /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 4. SSL/TLS com Let's Encrypt

```bash
# Instalar certbot
sudo apt-get install certbot python3-certbot-nginx

# Obter certificado
sudo certbot --nginx -d soar.company.com

# Renovação automática
sudo certbot renew --dry-run
```

### 5. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Verificar status
sudo ufw status
```

## Monitoramento

### 1. Logs

```bash
# Logs da aplicação
tail -f /var/log/mini-soar/soar.log

# Logs do Nginx
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Logs do systemd
journalctl -u soar -f
```

### 2. Health Check

```bash
# Script de health check
#!/bin/bash
HEALTH_URL="http://localhost:8000/"

response=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $response -eq 200 ]; then
    echo "OK: SOAR API is healthy"
    exit 0
else
    echo "CRITICAL: SOAR API is down (HTTP $response)"
    exit 2
fi
```

### 3. Prometheus Metrics (Para adicionar)

Adicionar ao `main.py`:

```python
from prometheus_client import Counter, Histogram, generate_latest

# Métricas
events_counter = Counter('soar_events_total', 'Total events received')
incidents_counter = Counter('soar_incidents_total', 'Total incidents created')
blocked_ips_counter = Counter('soar_blocked_ips_total', 'Total IPs blocked')

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### 4. Grafana Dashboard

Exemplo de queries para dashboard:

```promql
# Taxa de eventos por segundo
rate(soar_events_total[5m])

# Incidentes por severidade
sum by (severity) (soar_incidents_total)

# IPs bloqueados por hora
increase(soar_blocked_ips_total[1h])
```

## Backup e Recuperação

### 1. Backup do Banco de Dados

```bash
#!/bin/bash
# backup_db.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/soar"
DB_PATH="/var/lib/mini-soar/soar_database.db"

mkdir -p $BACKUP_DIR

# Backup SQLite
sqlite3 $DB_PATH ".backup '$BACKUP_DIR/soar_$DATE.db'"

# Comprimir
gzip $BACKUP_DIR/soar_$DATE.db

# Manter apenas últimos 7 dias
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Backup completed: soar_$DATE.db.gz"
```

Agendar com cron:

```bash
# Executar backup diário às 2h da manhã
0 2 * * * /opt/mini-soar/backup_db.sh
```

### 2. Restauração

```bash
# Parar serviço
sudo systemctl stop soar

# Restaurar backup
gunzip -c /backup/soar/soar_20251114_020000.db.gz > /var/lib/mini-soar/soar_database.db

# Reiniciar serviço
sudo systemctl start soar
```

### 3. Backup Completo

```bash
#!/bin/bash
# full_backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/soar-full"

mkdir -p $BACKUP_DIR

# Backup de código, configs e banco
tar -czf $BACKUP_DIR/soar-full-$DATE.tar.gz \
    /opt/mini-soar \
    /var/lib/mini-soar \
    /etc/systemd/system/soar.service \
    /etc/nginx/sites-available/soar

echo "Full backup completed: soar-full-$DATE.tar.gz"
```

## Melhorias para Produção

### 1. Autenticação e Autorização

```python
from fastapi import Security, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

@app.post("/events")
async def receive_event(
    event: SecurityEvent,
    user = Depends(verify_token)
):
    # ... código existente
```

### 2. Rate Limiting

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/events")
@limiter.limit("100/minute")
async def receive_event(request: Request, event: SecurityEvent):
    # ... código existente
```

### 3. PostgreSQL ao invés de SQLite

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://soar:password@localhost/soar"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

### 4. Cache com Redis

```python
import redis
from functools import wraps

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def cache_result(ttl=300):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            cached = redis_client.get(cache_key)
            
            if cached:
                return json.loads(cached)
            
            result = await func(*args, **kwargs)
            redis_client.setex(cache_key, ttl, json.dumps(result))
            return result
        return wrapper
    return decorator

@cache_result(ttl=3600)
async def check_threat_intel(ip: str):
    # ... código existente
```

### 5. Testes Automatizados

```python
# test_api.py
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_receive_event():
    response = client.post("/events", json={
        "event_type": "failed_login",
        "source_ip": "192.168.1.1",
        "severity": "medium",
        "description": "Test event"
    })
    assert response.status_code == 201

def test_get_stats():
    response = client.get("/stats")
    assert response.status_code == 200
    assert "total_events" in response.json()
```

### 6. CI/CD Pipeline

`.github/workflows/deploy.yml`:

```yaml
name: Deploy SOAR

on:
  push:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        run: |
          ssh user@server 'cd /opt/mini-soar && git pull && docker-compose up -d --build'
```

### 7. Integração com SIEM Real

```python
# Exemplo: Splunk
import splunklib.client as client

service = client.connect(
    host="splunk.company.com",
    port=8089,
    username="admin",
    password="password"
)

async def send_to_splunk(event_data):
    index = service.indexes["security"]
    index.submit(json.dumps(event_data))
```

### 8. Webhook Notifications

```python
async def send_webhook(url: str, data: dict):
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=data)
        return response.status_code == 200
```

## Checklist de Produção

- [ ] Autenticação implementada
- [ ] HTTPS configurado
- [ ] Rate limiting habilitado
- [ ] Logs centralizados
- [ ] Backup automatizado
- [ ] Monitoramento ativo
- [ ] Health checks configurados
- [ ] PostgreSQL ao invés de SQLite
- [ ] Redis para cache
- [ ] Documentação atualizada
- [ ] Testes automatizados
- [ ] CI/CD pipeline
- [ ] Firewall configurado
- [ ] Variáveis de ambiente seguras
- [ ] Integração com SIEM real
- [ ] Alertas funcionando
- [ ] Playbooks testados

## Suporte

Para questões de deployment:

1. Verifique os logs
2. Teste os health checks
3. Valide configurações
4. Consulte a documentação

---

**Boa sorte com seu deployment!** 🚀