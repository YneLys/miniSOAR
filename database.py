"""
Módulo de gerenciamento de banco de dados
Fornece context managers e abstração para operações com SQLite
"""
import sqlite3
import logging
from contextlib import contextmanager
from typing import Generator, Optional
from pathlib import Path
import os

from config import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Gerenciador de conexões com o banco de dados SQLite"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.DB_PATH
        self._ensure_db_directory()
        self._init_database()
    
    def _ensure_db_directory(self):
        """Garante que o diretório do banco existe"""
        db_file = Path(self.db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self):
        """Inicializa o banco de dados criando as tabelas necessárias"""
        try:
            with self.get_connection() as conn:
                self._create_tables(conn)
            logger.info(f"Banco de dados inicializado: {self.db_path}")
        except Exception as e:
            logger.error(f"Erro ao inicializar banco de dados: {e}")
            raise
    
    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager para obter conexão com o banco de dados
        Garante que a conexão seja fechada corretamente
        """
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0
            )
            conn.row_factory = sqlite3.Row  # Permite acesso por nome de coluna
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Erro na operação do banco de dados: {e}")
            raise
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Erro inesperado no banco de dados: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    @contextmanager
    def get_cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """
        Context manager para obter cursor do banco de dados
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
            finally:
                cursor.close()
    
    def _create_tables(self, conn: sqlite3.Connection):
        """Cria todas as tabelas necessárias"""
        cursor = conn.cursor()
        
        # Tabela de eventos
        cursor.execute('''CREATE TABLE IF NOT EXISTS events
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          event_type TEXT NOT NULL,
                          source_ip TEXT NOT NULL,
                          destination_ip TEXT,
                          username TEXT,
                          severity TEXT NOT NULL,
                          description TEXT NOT NULL,
                          timestamp TEXT NOT NULL,
                          processed INTEGER DEFAULT 0,
                          created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        
        # Índices para melhor performance
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_events_source_ip 
                         ON events(source_ip)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                         ON events(timestamp)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_events_processed 
                         ON events(processed)''')
        
        # Tabela de IPs bloqueados
        cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          ip TEXT UNIQUE NOT NULL,
                          reason TEXT NOT NULL,
                          blocked_at TEXT NOT NULL,
                          active INTEGER DEFAULT 1,
                          created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_blocked_ips_active 
                         ON blocked_ips(active)''')
        
        # Tabela de incidentes
        cursor.execute('''CREATE TABLE IF NOT EXISTS incidents
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          event_id INTEGER,
                          status TEXT NOT NULL,
                          actions_taken TEXT,
                          created_at TEXT NOT NULL,
                          resolved_at TEXT,
                          FOREIGN KEY (event_id) REFERENCES events(id))''')
        
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_incidents_status 
                         ON incidents(status)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_incidents_created_at 
                         ON incidents(created_at)''')
        
        # Tabela de alertas
        cursor.execute('''CREATE TABLE IF NOT EXISTS alerts
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          incident_id INTEGER,
                          alert_type TEXT NOT NULL,
                          message TEXT NOT NULL,
                          sent_at TEXT NOT NULL,
                          channel TEXT,
                          status TEXT DEFAULT 'sent',
                          FOREIGN KEY (incident_id) REFERENCES incidents(id))''')
        
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_alerts_incident_id 
                         ON alerts(incident_id)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_alerts_sent_at 
                         ON alerts(sent_at)''')
        
        conn.commit()
        logger.debug("Tabelas do banco de dados criadas/verificadas")
    
    def execute_query(self, query: str, params: tuple = ()) -> list:
        """
        Executa uma query SELECT e retorna os resultados
        """
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """
        Executa uma query INSERT/UPDATE/DELETE e retorna o número de linhas afetadas
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows_affected = cursor.rowcount
            conn.commit()
            return rows_affected
    
    def execute_insert(self, query: str, params: tuple = ()) -> int:
        """
        Executa uma query INSERT e retorna o ID da última linha inserida
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            last_id = cursor.lastrowid
            conn.commit()
            return last_id


# Instância global do gerenciador de banco de dados
db_manager = DatabaseManager()

