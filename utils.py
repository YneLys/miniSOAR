"""
Utilitários para retry logic e circuit breaker
"""
import asyncio
import time
from typing import Callable, Any, Optional
from enum import Enum
from datetime import datetime, timedelta

from config import settings
from logger import get_logger
from exceptions import CircuitBreakerError

logger = get_logger(__name__)


class CircuitState(Enum):
    """Estados do circuit breaker"""
    CLOSED = "closed"  # Funcionando normalmente
    OPEN = "open"  # Falhou, bloqueando requisições
    HALF_OPEN = "half_open"  # Testando se recuperou


class CircuitBreaker:
    """Circuit breaker para proteger contra falhas em cascata"""
    
    def __init__(
        self,
        failure_threshold: int = None,
        timeout_seconds: int = None,
        name: str = "default"
    ):
        self.failure_threshold = failure_threshold or settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD
        self.timeout_seconds = timeout_seconds or settings.CIRCUIT_BREAKER_TIMEOUT_SECONDS
        self.name = name
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.success_count = 0
    
    def can_execute(self) -> bool:
        """Verifica se pode executar uma operação"""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Verificar se já passou o timeout
            if self.last_failure_time:
                elapsed = (datetime.now() - self.last_failure_time).total_seconds()
                if elapsed >= self.timeout_seconds:
                    logger.info(f"Circuit breaker {self.name} mudando para HALF_OPEN")
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    return True
            return False
        
        # HALF_OPEN - permite tentar
        return True
    
    def record_success(self):
        """Registra uma operação bem-sucedida"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= 2:  # Precisa de 2 sucessos para fechar
                logger.info(f"Circuit breaker {self.name} fechado após recuperação")
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0
    
    def record_failure(self):
        """Registra uma falha"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            logger.warning(
                f"Circuit breaker {self.name} aberto após {self.failure_count} falhas"
            )
            self.state = CircuitState.OPEN
        elif self.state == CircuitState.HALF_OPEN:
            # Falhou no teste, voltar para OPEN
            logger.warning(f"Circuit breaker {self.name} voltou para OPEN após falha no teste")
            self.state = CircuitState.OPEN


async def retry_async(
    func: Callable,
    max_attempts: int = None,
    delay: float = None,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    circuit_breaker: Optional[CircuitBreaker] = None
) -> Any:
    """
    Executa uma função assíncrona com retry logic
    
    Args:
        func: Função assíncrona a ser executada
        max_attempts: Número máximo de tentativas
        delay: Delay inicial entre tentativas (em segundos)
        backoff: Multiplicador para backoff exponencial
        exceptions: Tupla de exceções que devem triggerar retry
        circuit_breaker: Circuit breaker opcional
    
    Returns:
        Resultado da função
    
    Raises:
        CircuitBreakerError: Se circuit breaker estiver aberto
        Exception: Última exceção se todas as tentativas falharem
    """
    max_attempts = max_attempts or settings.RETRY_MAX_ATTEMPTS
    delay = delay or settings.RETRY_DELAY_SECONDS
    
    last_exception = None
    
    for attempt in range(1, max_attempts + 1):
        # Verificar circuit breaker
        if circuit_breaker and not circuit_breaker.can_execute():
            raise CircuitBreakerError(
                f"Circuit breaker {circuit_breaker.name} está aberto",
                {"circuit_breaker": circuit_breaker.name, "state": circuit_breaker.state.value}
            )
        
        try:
            result = await func()
            
            # Registrar sucesso no circuit breaker
            if circuit_breaker:
                circuit_breaker.record_success()
            
            if attempt > 1:
                logger.info(f"Operação bem-sucedida na tentativa {attempt}")
            
            return result
            
        except exceptions as e:
            last_exception = e
            
            # Registrar falha no circuit breaker
            if circuit_breaker:
                circuit_breaker.record_failure()
            
            if attempt < max_attempts:
                wait_time = delay * (backoff ** (attempt - 1))
                logger.warning(
                    f"Tentativa {attempt}/{max_attempts} falhou: {str(e)}. "
                    f"Tentando novamente em {wait_time:.2f}s"
                )
                await asyncio.sleep(wait_time)
            else:
                logger.error(
                    f"Todas as {max_attempts} tentativas falharam. Último erro: {str(e)}"
                )
    
    # Todas as tentativas falharam
    raise last_exception


def retry_sync(
    func: Callable,
    max_attempts: int = None,
    delay: float = None,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    circuit_breaker: Optional[CircuitBreaker] = None
) -> Any:
    """
    Executa uma função síncrona com retry logic
    
    Args:
        func: Função síncrona a ser executada
        max_attempts: Número máximo de tentativas
        delay: Delay inicial entre tentativas (em segundos)
        backoff: Multiplicador para backoff exponencial
        exceptions: Tupla de exceções que devem triggerar retry
        circuit_breaker: Circuit breaker opcional
    
    Returns:
        Resultado da função
    
    Raises:
        CircuitBreakerError: Se circuit breaker estiver aberto
        Exception: Última exceção se todas as tentativas falharem
    """
    max_attempts = max_attempts or settings.RETRY_MAX_ATTEMPTS
    delay = delay or settings.RETRY_DELAY_SECONDS
    
    last_exception = None
    
    for attempt in range(1, max_attempts + 1):
        # Verificar circuit breaker
        if circuit_breaker and not circuit_breaker.can_execute():
            raise CircuitBreakerError(
                f"Circuit breaker {circuit_breaker.name} está aberto",
                {"circuit_breaker": circuit_breaker.name, "state": circuit_breaker.state.value}
            )
        
        try:
            result = func()
            
            # Registrar sucesso no circuit breaker
            if circuit_breaker:
                circuit_breaker.record_success()
            
            if attempt > 1:
                logger.info(f"Operação bem-sucedida na tentativa {attempt}")
            
            return result
            
        except exceptions as e:
            last_exception = e
            
            # Registrar falha no circuit breaker
            if circuit_breaker:
                circuit_breaker.record_failure()
            
            if attempt < max_attempts:
                wait_time = delay * (backoff ** (attempt - 1))
                logger.warning(
                    f"Tentativa {attempt}/{max_attempts} falhou: {str(e)}. "
                    f"Tentando novamente em {wait_time:.2f}s"
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    f"Todas as {max_attempts} tentativas falharam. Último erro: {str(e)}"
                )
    
    # Todas as tentativas falharam
    raise last_exception

