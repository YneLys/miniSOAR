import requests
import time
import json

BASE_URL = "http://localhost:8000"

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def test_api_health():
    print_section("1. Testando Health da API")
    response = requests.get(f"{BASE_URL}/")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def simulate_failed_logins():
    print_section("2. Simulando Tentativas de Login Falhadas")
    malicious_ip = "192.168.1.100"
    
    for i in range(6):
        event = {
            "event_type": "failed_login",
            "source_ip": malicious_ip,
            "username": f"admin{i}",
            "severity": "medium",
            "description": f"Failed login attempt #{i+1} for user admin{i}"
        }
        response = requests.post(f"{BASE_URL}/events", json=event)
        print(f"Tentativa {i+1}: {response.json()['message']}")
        time.sleep(0.5)
    
    print("\nAguardando processamento da automação...")
    time.sleep(3)
    
    blocked = requests.get(f"{BASE_URL}/blocked-ips")
    print(f"\nIPs Bloqueados: {blocked.json()['count']}")
    
    if blocked.json()['count'] > 0:
        print("AUTOMAÇÃO FUNCIONOU! IP bloqueado automaticamente!")

def simulate_critical_event():
    print_section("3. Simulando Evento Crítico")
    event = {
        "event_type": "malware_detected",
        "source_ip": "10.0.0.50",
        "severity": "critical",
        "description": "Ransomware activity detected on endpoint"
    }
    response = requests.post(f"{BASE_URL}/events", json=event)
    print(f"Evento enviado: {response.json()['message']}")
    time.sleep(2)
    
    alerts = requests.get(f"{BASE_URL}/alerts")
    print(f"\nAlertas Enviados: {alerts.json()['count']}")

def simulate_known_threat():
    print_section("4. Simulando Acesso de IP Malicioso Conhecido")
    event = {
        "event_type": "suspicious_connection",
        "source_ip": "172.16.0.200",
        "destination_ip": "192.168.1.10",
        "severity": "high",
        "description": "Connection attempt from known malware C2 server"
    }
    response = requests.post(f"{BASE_URL}/events", json=event)
    print(f"Evento enviado: {response.json()['message']}")
    time.sleep(2)
    
    blocked = requests.get(f"{BASE_URL}/blocked-ips")
    print(f"\nTotal de IPs bloqueados: {blocked.json()['count']}")

def simulate_port_scan():
    print_section("5. Simulando Port Scan")
    scanner_ip = "203.0.113.50"
    
    for port in [22, 80, 443, 3389, 8080]:
        event = {
            "event_type": "port_scan",
            "source_ip": scanner_ip,
            "destination_ip": "192.168.1.5",
            "severity": "medium",
            "description": f"Port scan detected on port {port}"
        }
        requests.post(f"{BASE_URL}/events", json=event)
        print(f"Port {port} escaneado detectado")
        time.sleep(0.3)

def manual_block_test():
    print_section("6. Testando Bloqueio Manual")
    block_data = {
        "ip": "198.51.100.25",
        "reason": "Manual block - Suspicious activity reported by analyst"
    }
    response = requests.post(f"{BASE_URL}/block-ip", json=block_data)
    result = response.json()
    print(f"Status: {result['status']}")
    print(f"Mensagem: {result['message']}")

def view_statistics():
    print_section("7. Estatísticas do Sistema")
    stats = requests.get(f"{BASE_URL}/stats").json()
    
    print(f"Total de Eventos: {stats['total_events']}")
    print(f"IPs Bloqueados Ativos: {stats['active_blocked_ips']}")
    print(f"Total de Incidentes: {stats['total_incidents']}")
    print(f"Total de Alertas: {stats['total_alerts']}")
    
    print("\nEventos por Severidade:")
    for severity, count in stats['severity_breakdown'].items():
        print(f"  - {severity.upper()}: {count}")

def view_recent_incidents():
    print_section("8. Incidentes Recentes")
    incidents = requests.get(f"{BASE_URL}/incidents?limit=5").json()
    print(f"Total: {incidents['count']} incidentes\n")
    
    for incident in incidents['incidents'][:3]:
        print(f"Incidente #{incident['id']}")
        print(f"  Status: {incident['status']}")
        actions = ', '.join(incident['actions_taken']) if incident['actions_taken'] else 'Nenhuma'
        print(f"  Ações tomadas: {actions}")
        print(f"  Criado em: {incident['created_at']}")
        print()

def main():
    print("\n" + "="*60)
    print("  MINI SOAR - SUITE DE TESTES")
    print("="*60)
    
    try:
        if not test_api_health():
            print("API não está respondendo.")
            return
        
        simulate_failed_logins()
        simulate_critical_event()
        simulate_known_threat()
        simulate_port_scan()
        manual_block_test()
        
        print("\nAguardando processamento final...")
        time.sleep(2)
        
        view_statistics()
        view_recent_incidents()
        
        print_section("TESTES CONCLUÍDOS COM SUCESSO!")
        print("\nPróximos passos:")
        print("  1. http://localhost:8000/docs - Documentação interativa")
        print("  2. http://localhost:8000/events - Ver eventos")
        print("  3. http://localhost:8000/blocked-ips - IPs bloqueados")
        print("  4. http://localhost:8000/stats - Estatísticas")
        
    except requests.exceptions.ConnectionError:
        print("\nErro: Não foi possível conectar à API.")
        print("Execute: python main.py ou docker-compose up")
    except Exception as e:
        print(f"\nErro: {str(e)}")

if __name__ == "__main__":
    main()