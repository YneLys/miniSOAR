"""
Playbook: Threat Intelligence
Descrição: Verifica IPs contra bases de threat intelligence
"""
from datetime import datetime

from validators import validate_ip
from logger import get_logger
from exceptions import ThreatIntelError, IPValidationError
from utils import retry_async, CircuitBreaker

logger = get_logger(__name__)

# Circuit breaker para APIs de threat intelligence
threat_intel_circuit_breaker = CircuitBreaker(
    name="threat_intel",
    failure_threshold=5,
    timeout_seconds=120
)

# Base simulada de IPs maliciosos conhecidos
KNOWN_MALICIOUS_IPS = {
    "192.168.1.100": {
        "threat_type": "botnet",
        "first_seen": "2024-01-15",
        "last_seen": "2025-11-10",
        "reputation_score": 95,
        "source": "AbuseIPDB"
    },
    "10.0.0.50": {
        "threat_type": "brute_force",
        "first_seen": "2024-06-20",
        "last_seen": "2025-11-12",
        "reputation_score": 88,
        "source": "OTX AlienVault"
    },
    "172.16.0.200": {
        "threat_type": "malware_c2",
        "first_seen": "2023-12-01",
        "last_seen": "2025-11-13",
        "reputation_score": 98,
        "source": "ThreatFox"
    },
    "203.0.113.50": {
        "threat_type": "scanner",
        "first_seen": "2025-10-01",
        "last_seen": "2025-11-14",
        "reputation_score": 75,
        "source": "GreyNoise"
    }
}

# Ranges de IPs suspeitos (simulado)
SUSPICIOUS_RANGES = [
    ("45.0.0.0", "45.255.255.255", "Known hosting of malicious activity"),
    ("185.0.0.0", "185.255.255.255", "Bulletproof hosting range"),
]

async def check_threat_intel(ip: str) -> dict:
    """
    Verifica IP contra bases de threat intelligence com retry logic
    
    Args:
        ip: Endereço IP a ser verificado
    
    Returns:
        dict com informações de threat intel
    """
    try:
        # Validar IP
        try:
            ip = validate_ip(ip)
        except IPValidationError as e:
            raise ThreatIntelError(f"IP inválido: {ip}", {"ip": ip})
        
        logger.info(f"Verificando threat intelligence para IP: {ip}", extra={"ip": ip})
        
        result = {
            "ip": ip,
            "is_malicious": False,
            "reputation_score": 0,
            "threat_type": None,
            "sources": [],
            "details": {},
            "timestamp": datetime.now().isoformat()
        }
        
        # Verificar em base de IPs conhecidos
        if ip in KNOWN_MALICIOUS_IPS:
            threat_data = KNOWN_MALICIOUS_IPS[ip]
            result["is_malicious"] = True
            result["reputation_score"] = threat_data["reputation_score"]
            result["threat_type"] = threat_data["threat_type"]
            result["sources"].append(threat_data["source"])
            result["details"] = threat_data
            
            logger.warning(f"IP {ip} encontrado em base de ameaças!")
            return result
        
        # Verificar ranges suspeitos
        suspicious_check = check_suspicious_range(ip)
        if suspicious_check["is_suspicious"]:
            result["is_malicious"] = True
            result["reputation_score"] = 60
            result["threat_type"] = "suspicious_range"
            result["sources"].append("Internal IP Range Analysis")
            result["details"] = suspicious_check
            
            logger.warning(f"IP {ip} está em range suspeito!")
            return result
        
        # Simular verificação em APIs externas com retry
        async def _check_external():
            return simulate_external_threat_check(ip)
        
        try:
            external_check = await retry_async(
                _check_external,
                max_attempts=3,
                delay=1.0,
                circuit_breaker=threat_intel_circuit_breaker
            )
            result.update(external_check)
        except Exception as e:
            logger.warning(f"Erro ao verificar APIs externas (continuando): {e}", extra={"ip": ip})
            # Continuar mesmo se falhar - já temos dados da base local
        
        if result["is_malicious"]:
            logger.warning(f"IP {ip} identificado como malicioso por fontes externas!")
        else:
            logger.info(f"IP {ip} não encontrado em bases de ameaças")
        
        return result
        
    except ThreatIntelError:
        raise
    except Exception as e:
        logger.error(f"Erro ao verificar threat intel: {e}", extra={"ip": ip}, exc_info=True)
        raise ThreatIntelError(f"Erro ao verificar threat intel: {str(e)}", {"ip": ip})

def check_suspicious_range(ip: str) -> dict:
    """Verifica se IP está em range suspeito"""
    try:
        ip_int = ip_to_int(ip)
        
        for start_ip, end_ip, reason in SUSPICIOUS_RANGES:
            start_int = ip_to_int(start_ip)
            end_int = ip_to_int(end_ip)
            
            if start_int <= ip_int <= end_int:
                return {
                    "is_suspicious": True,
                    "range": f"{start_ip} - {end_ip}",
                    "reason": reason
                }
        
        return {"is_suspicious": False}
        
    except Exception:
        return {"is_suspicious": False}

def ip_to_int(ip: str) -> int:
    """Converte IP string para inteiro"""
    parts = ip.split(".")
    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))

async def simulate_external_threat_check(ip: str) -> dict:
    """
    Simula verificação em APIs externas de threat intelligence
    Em produção: fazer requests reais para APIs
    """
    # Simular algumas características que indicam ameaça
    ip_parts = [int(p) for p in ip.split(".")]
    
    # Heurística simples para demo
    suspicious_score = 0
    
    # IPs começando com certos octetos são mais suspeitos (simulação)
    if ip_parts[0] in [45, 185, 91]:
        suspicious_score += 30
    
    # Octeto final muito alto ou muito baixo pode indicar scanner
    if ip_parts[3] < 10 or ip_parts[3] > 250:
        suspicious_score += 20
    
    # Simular check em múltiplas fontes
    sources_checked = [
        "AbuseIPDB (simulated)",
        "VirusTotal (simulated)",
        "OTX AlienVault (simulated)",
        "GreyNoise (simulated)"
    ]
    
    is_malicious = suspicious_score >= 40
    
    return {
        "reputation_score": suspicious_score,
        "is_malicious": is_malicious,
        "threat_type": "potential_scanner" if is_malicious else None,
        "sources": sources_checked if is_malicious else [],
        "confidence": "medium" if is_malicious else "low"
    }

async def enrich_event_with_intel(event_data: dict) -> dict:
    """
    Enriquece evento com dados de threat intelligence
    """
    logger.info(f"Enriquecendo evento com threat intelligence")
    
    enriched = event_data.copy()
    
    # Verificar source IP
    if "source_ip" in event_data and event_data["source_ip"]:
        source_intel = await check_threat_intel(event_data["source_ip"])
        enriched["source_threat_intel"] = source_intel
    
    # Verificar destination IP
    if "destination_ip" in event_data and event_data["destination_ip"]:
        dest_intel = await check_threat_intel(event_data["destination_ip"])
        enriched["destination_threat_intel"] = dest_intel
    
    # Adicionar contexto
    enriched["enriched_at"] = datetime.now().isoformat()
    enriched["enrichment_sources"] = ["Internal Threat DB", "Simulated External APIs"]
    
    return enriched

async def get_threat_feed_updates() -> dict:
    """
    Simula atualização de feeds de threat intelligence
    Em produção: sincronizar com feeds STIX/TAXII
    """
    logger.info("Atualizando threat intelligence feeds...")
    
    return {
        "status": "success",
        "feeds_updated": [
            "AbuseIPDB",
            "OTX AlienVault",
            "ThreatFox",
            "GreyNoise"
        ],
        "new_indicators": 150,
        "updated_at": datetime.now().isoformat()
    }