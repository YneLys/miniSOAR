"""
Configuração centralizada de logging
Fornece logging estruturado e consistente para toda a aplicação
"""
import logging
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime

from config import settings


class JSONFormatter(logging.Formatter):
    """Formatter que produz logs em formato JSON estruturado"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Adicionar informações extras se existirem
        if hasattr(record, "correlation_id"):
            log_data["correlation_id"] = record.correlation_id
        
        if hasattr(record, "event_id"):
            log_data["event_id"] = record.event_id
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


class StructuredFormatter(logging.Formatter):
    """Formatter que produz logs estruturados legíveis"""
    
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)
        logger_name = record.name
        
        message = record.getMessage()
        
        # Adicionar informações extras
        extras = []
        if hasattr(record, "correlation_id"):
            extras.append(f"correlation_id={record.correlation_id}")
        if hasattr(record, "event_id"):
            extras.append(f"event_id={record.event_id}")
        
        extra_str = " | ".join(extras) if extras else ""
        extra_str = f" | {extra_str}" if extra_str else ""
        
        log_line = f"{timestamp} | {level} | {logger_name} | {message}{extra_str}"
        
        if record.exc_info:
            log_line += f"\n{self.formatException(record.exc_info)}"
        
        return log_line


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[str] = None,
    use_json: bool = False
) -> logging.Logger:
    """
    Configura o sistema de logging da aplicação
    
    Args:
        log_level: Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Caminho para arquivo de log (opcional)
        use_json: Se True, usa formato JSON, senão usa formato estruturado legível
    
    Returns:
        Logger configurado
    """
    level = getattr(logging, (log_level or settings.LOG_LEVEL).upper(), logging.INFO)
    
    # Criar logger raiz
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remover handlers existentes para evitar duplicação
    root_logger.handlers.clear()
    
    # Formatter
    if use_json:
        formatter = JSONFormatter()
    else:
        formatter = StructuredFormatter()
    
    # Handler para console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Handler para arquivo (se especificado)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Obtém um logger com o nome especificado
    
    Args:
        name: Nome do logger (geralmente __name__)
    
    Returns:
        Logger configurado
    """
    return logging.getLogger(name)


# Configurar logging na importação do módulo
setup_logging(
    log_level=settings.LOG_LEVEL,
    log_file=getattr(settings, 'LOG_FILE', None),
    use_json=getattr(settings, 'LOG_JSON', False)
)

# Logger padrão
logger = get_logger(__name__)

