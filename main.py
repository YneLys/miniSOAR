"""
Mini SOAR System - API Principal
Sistema de Security Orchestration, Automation and Response
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime
import traceback

# Importar módulos do sistema
from config import settings
from logger import get_logger, setup_logging
from database import db_manager
from exceptions import (
    SOARException, ValidationError, DatabaseError,
    BlockIPError, AlertError, ThreatIntelError
)
from services.event_service import EventService
from services.incident_service import IncidentService
from services.automation_service import AutomationService
from repositories import BlockedIPRepository, AlertRepository
from playbooks.block_ip import block_ip_playbook
from middleware import LoggingMiddleware, RateLimitMiddleware, get_correlation_id

# Configurar logging
setup_logging(
    log_level=settings.LOG_LEVEL,
    log_file=settings.LOG_FILE,
    use_json=settings.LOG_JSON
)

logger = get_logger(__name__)

# Criar aplicação FastAPI
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Sistema SOAR para automação de resposta a incidentes de segurança"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, especificar origens permitidas
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Adicionar middlewares customizados
app.add_middleware(LoggingMiddleware)
RateLimitMiddleware.setup_app(app)

# Inicializar serviços
event_service = EventService()
incident_service = IncidentService()
automation_service = AutomationService()
blocked_ip_repo = BlockedIPRepository()
alert_repo = AlertRepository()


# Modelos Pydantic
class SecurityEvent(BaseModel):
    """Modelo para evento de segurança"""
    event_type: str = Field(..., description="Tipo do evento")
    source_ip: str = Field(..., description="IP de origem")
    destination_ip: Optional[str] = Field(None, description="IP de destino")
    username: Optional[str] = Field(None, description="Nome de usuário")
    severity: str = Field(..., description="Nível de severidade (low, medium, high, critical)")
    description: str = Field(..., description="Descrição do evento")
    timestamp: Optional[str] = Field(None, description="Timestamp do evento (ISO format)")


class BlockedIPRequest(BaseModel):
    """Modelo para requisição de bloqueio de IP"""
    ip: str = Field(..., description="Endereço IP a ser bloqueado")
    reason: str = Field(..., description="Motivo do bloqueio")


class ErrorResponse(BaseModel):
    """Modelo para respostas de erro"""
    error: str
    detail: Optional[str] = None
    correlation_id: Optional[str] = None


# Exception handlers
@app.exception_handler(SOARException)
async def soar_exception_handler(request: Request, exc: SOARException):
    """Handler para exceções customizadas do SOAR"""
    correlation_id = get_correlation_id(request)
    logger.error(
        f"SOAR Exception: {exc.message}",
        extra={"correlation_id": correlation_id, "details": exc.details},
        exc_info=True
    )
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": exc.message,
            "detail": exc.details,
            "correlation_id": correlation_id
        }
    )


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """Handler para erros de validação"""
    correlation_id = get_correlation_id(request)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation error",
            "detail": exc.message,
            "correlation_id": correlation_id
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handler para exceções genéricas"""
    correlation_id = get_correlation_id(request)
    logger.error(
        f"Unexpected error: {str(exc)}",
        extra={"correlation_id": correlation_id},
        exc_info=True
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.LOG_LEVEL == "DEBUG" else "An unexpected error occurred",
            "correlation_id": correlation_id
        }
    )


# Startup e Shutdown
@app.on_event("startup")
async def startup():
    """Inicialização da aplicação"""
    try:
        # Banco de dados já é inicializado automaticamente pelo db_manager
        logger.info(
            f"🚀 {settings.API_TITLE} v{settings.API_VERSION} iniciado!",
            extra={"host": settings.API_HOST, "port": settings.API_PORT}
        )
    except Exception as e:
        logger.error(f"Erro na inicialização: {e}", exc_info=True)
        raise


@app.on_event("shutdown")
async def shutdown():
    """Finalização da aplicação"""
    logger.info("Aplicação sendo encerrada...")


# Endpoints
@app.get("/", tags=["Root"])
async def root(request: Request):
    """Endpoint raiz com informações da API"""
    correlation_id = get_correlation_id(request)
    return {
        "message": f"{settings.API_TITLE} API",
        "version": settings.API_VERSION,
        "correlation_id": correlation_id,
        "endpoints": {
            "POST /events": "Receber eventos de segurança",
            "GET /events": "Listar eventos",
            "GET /incidents": "Listar incidentes",
            "GET /blocked-ips": "Listar IPs bloqueados",
            "POST /block-ip": "Bloquear IP manualmente",
            "GET /alerts": "Listar alertas",
            "GET /stats": "Estatísticas do sistema",
            "GET /health": "Health check",
            "GET /metrics": "Métricas do sistema"
        }
    }


@app.post("/events", status_code=status.HTTP_201_CREATED, tags=["Events"])
async def receive_event(
    event: SecurityEvent,
    background_tasks: BackgroundTasks,
    request: Request
):
    """
    Endpoint para receber eventos de segurança (simulando SIEM)
    O evento é processado automaticamente em background
    """
    correlation_id = get_correlation_id(request)
    
    try:
        logger.info(
            f"Recebendo evento: {event.event_type}",
            extra={
                "correlation_id": correlation_id,
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "severity": event.severity
            }
        )
        
        # Criar evento usando serviço
        result = event_service.create_event(
            event_type=event.event_type,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=event.username,
            severity=event.severity,
            description=event.description,
            timestamp=event.timestamp
        )
        
        event_id = result["event_id"]
        incident_id = result["incident_id"]
        
        # Processar automação em background
        async def process_automation():
            try:
                event_data = {
                    "event_type": event.event_type,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "severity": event.severity,
                    "description": event.description
                }
                await automation_service.process_event(event_id, event_data)
            except Exception as e:
                logger.error(
                    f"Erro no processamento automático do evento {event_id}: {e}",
                    extra={"event_id": event_id, "correlation_id": correlation_id},
                    exc_info=True
                )
        
        background_tasks.add_task(process_automation)
        
        return {
            "status": "Event received",
            "event_id": event_id,
            "incident_id": incident_id,
            "message": "Event is being processed by automation engine",
            "correlation_id": correlation_id
        }
        
    except ValidationError as e:
        raise
    except Exception as e:
        logger.error(
            f"Erro ao receber evento: {e}",
            extra={"correlation_id": correlation_id},
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar evento: {str(e)}"
        )


@app.get("/events", tags=["Events"])
async def list_events(
    limit: int = 50,
    offset: int = 0,
    processed: Optional[bool] = None,
    severity: Optional[str] = None,
    request: Request = None
):
    """Listar eventos recentes com filtros opcionais"""
    try:
        result = event_service.list_events(
            limit=limit,
            offset=offset,
            processed=processed,
            severity=severity
        )
        return result
    except ValidationError as e:
        raise
    except Exception as e:
        logger.error(f"Erro ao listar eventos: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/incidents", tags=["Incidents"])
async def list_incidents(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None
):
    """Listar incidentes com filtros opcionais"""
    try:
        return incident_service.list_incidents(
            limit=limit,
            offset=offset,
            status=status
        )
    except ValidationError as e:
        raise
    except Exception as e:
        logger.error(f"Erro ao listar incidentes: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/blocked-ips", tags=["Blocked IPs"])
async def list_blocked_ips(active_only: bool = True, limit: int = 100):
    """Listar IPs bloqueados"""
    try:
        blocked_ips = blocked_ip_repo.list(active_only=active_only, limit=limit)
        return {
            "blocked_ips": blocked_ips,
            "count": len(blocked_ips)
        }
    except Exception as e:
        logger.error(f"Erro ao listar IPs bloqueados: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.post("/block-ip", tags=["Blocked IPs"])
async def manual_block_ip(data: BlockedIPRequest, request: Request):
    """Bloquear IP manualmente"""
    correlation_id = get_correlation_id(request)
    
    try:
        logger.info(
            f"Bloqueio manual solicitado para IP: {data.ip}",
            extra={"ip": data.ip, "correlation_id": correlation_id}
        )
        
        result = await block_ip_playbook(data.ip, data.reason)
        return result
    except BlockIPError as e:
        raise
    except Exception as e:
        logger.error(
            f"Erro ao bloquear IP: {e}",
            extra={"ip": data.ip, "correlation_id": correlation_id},
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/alerts", tags=["Alerts"])
async def list_alerts(
    limit: int = 50,
    offset: int = 0,
    incident_id: Optional[int] = None,
    alert_type: Optional[str] = None
):
    """Listar alertas enviados"""
    try:
        alerts = alert_repo.list(
            limit=limit,
            offset=offset,
            incident_id=incident_id,
            alert_type=alert_type
        )
        return {
            "alerts": alerts,
            "count": len(alerts)
        }
    except Exception as e:
        logger.error(f"Erro ao listar alertas: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/stats", tags=["Statistics"])
async def get_stats():
    """Estatísticas do sistema"""
    try:
        # Estatísticas de eventos
        event_stats = event_service.get_statistics()
        
        # IPs bloqueados ativos
        active_blocked = blocked_ip_repo.count_active()
        
        # Total de incidentes
        from repositories import IncidentRepository
        incident_repo = IncidentRepository()
        total_incidents = incident_repo.count()
        
        # Total de alertas
        total_alerts = alert_repo.count()
        
        return {
            "total_events": event_stats.get("total_events", 0),
            "severity_breakdown": event_stats.get("severity_breakdown", {}),
            "active_blocked_ips": active_blocked,
            "total_incidents": total_incidents,
            "total_alerts": total_alerts,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check robusto do sistema"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": settings.API_VERSION,
            "checks": {}
        }
        
        # Verificar banco de dados
        try:
            with db_manager.get_connection() as conn:
                conn.execute("SELECT 1")
            health_status["checks"]["database"] = "ok"
        except Exception as e:
            health_status["checks"]["database"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
        
        # Verificar serviços
        try:
            # Testar repositórios
            blocked_ip_repo.count_active()
            health_status["checks"]["repositories"] = "ok"
        except Exception as e:
            health_status["checks"]["repositories"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
        
        status_code = status.HTTP_200_OK if health_status["status"] == "healthy" else status.HTTP_503_SERVICE_UNAVAILABLE
        
        return JSONResponse(
            status_code=status_code,
            content=health_status
        )
    except Exception as e:
        logger.error(f"Erro no health check: {e}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Métricas do sistema para monitoramento"""
    try:
        stats = await get_stats()
        
        # Adicionar métricas adicionais
        metrics = {
            **stats,
            "system": {
                "version": settings.API_VERSION,
                "rate_limit_enabled": settings.RATE_LIMIT_ENABLED,
                "threat_intel_enabled": settings.ENABLE_THREAT_INTEL
            }
        }
        
        return metrics
    except Exception as e:
        logger.error(f"Erro ao obter métricas: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=settings.LOG_LEVEL.lower()
    )
