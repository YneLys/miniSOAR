"""
Middlewares para a aplicação FastAPI
Inclui rate limiting, logging de requisições e correlation IDs
"""
import time
import uuid
from typing import Callable
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from logger import get_logger
from exceptions import RateLimitError

logger = get_logger(__name__)

# Configurar rate limiter
limiter = Limiter(key_func=get_remote_address)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware para logging de requisições HTTP"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Gerar correlation ID
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        
        # Adicionar correlation ID ao logger
        logger_adapter = logger.getChild("http")
        
        # Log da requisição recebida
        start_time = time.time()
        client_ip = get_remote_address(request)
        
        logger_adapter.info(
            f"Request: {request.method} {request.url.path}",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "query_params": str(request.query_params)
            }
        )
        
        try:
            # Processar requisição
            response = await call_next(request)
            
            # Calcular tempo de processamento
            process_time = time.time() - start_time
            
            # Adicionar headers de resposta
            response.headers["X-Correlation-ID"] = correlation_id
            response.headers["X-Process-Time"] = f"{process_time:.4f}"
            
            # Log da resposta
            logger_adapter.info(
                f"Response: {request.method} {request.url.path} - {response.status_code}",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "process_time": process_time
                }
            )
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger_adapter.error(
                f"Error processing request: {request.method} {request.url.path}",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "process_time": process_time
                },
                exc_info=True
            )
            
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "Internal server error",
                    "correlation_id": correlation_id
                },
                headers={"X-Correlation-ID": correlation_id}
            )


class RateLimitMiddleware:
    """Middleware para rate limiting (usado via slowapi)"""
    
    @staticmethod
    def setup_app(app):
        """Configura rate limiting na aplicação"""
        if settings.RATE_LIMIT_ENABLED:
            app.state.limiter = limiter
            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
            logger.info(f"Rate limiting habilitado: {settings.RATE_LIMIT_PER_MINUTE} req/min")
        else:
            logger.info("Rate limiting desabilitado")


def get_correlation_id(request: Request) -> str:
    """Obtém o correlation ID da requisição"""
    return getattr(request.state, "correlation_id", "unknown")

