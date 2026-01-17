"""
Integrated Network and Vulnerability Scanner
Combines network service discovery with vulnerability assessment
"""

import json
import time
from typing import List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.layout import Layout

from network_scanner import NetworkScanner, ServiceInfo
from vulnerability_scanner import VulnerabilityScanner, Vulnerability

class IntegratedSecurityScanner:
    """Escáner de seguridad integrado: red + vulnerabilidades"""
    
    def __init__(self):
        self.console = Console()
        self.network_scanner = NetworkScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.results = {
            'services': [],
            'vulnerabilities': [],
            'scan_time': None,
            'targets': []
        }
    
    def scan_target(self, target: str, ports: str = "1-1000") -> Dict:
        """
        Ejecuta escaneo completo: red → servicios → vulnerabilidades
        
        Args:
            target: IP o rango a escanear
            ports: Rango de puertos
        
        Returns:
            Diccionario con resultados completos
        """
        self.console.print(Panel.fit(
            f"[bold cyan]Integrated Security Scanner[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Ports: [yellow]{ports}[/yellow]",
            border_style="cyan"
        ))
        
        # Paso 1: Escaneo de red
        self.console.print("\n[bold]Phase 1: Network Service Discovery[/bold]")
        services = self.network_scanner.scan_network(target, ports)
        
        if not services:
            self.console.print("[yellow]No services found. Exiting.[/yellow]")
            return self.results
        
        # Mostrar servicios encontrados
        self.network_scanner.pretty_print_services(services)
        
        # Paso 2: Convertir servicios a formato para escáner de vulnerabilidades
        service_dicts = []
        for service in services:
            service_dict = service.to_dict()
            # Agregar campo combinado para búsqueda
            service_dict['search_term'] = f"{service.service_name} {service.version}".strip()
            service_dicts.append(service_dict)
        
        # Paso 3: Escaneo de vulnerabilidades
        self.console.print("\n[bold]Phase 2: Vulnerability Assessment[/bold]")
        
        # Filtrar servicios para análisis (priorizar no seguros y conocidos)
        services_to_scan = self._prioritize_services(service_dicts)
        
        # Escanear vulnerabilidades
        vuln_results = self.vuln_scanner.scan_services(services_to_scan)
        
        # Consolidar resultados
        all_vulnerabilities = []
        for key, vulns in vuln_results.items():
            all_vulnerabilities.extend(vulns)
        
        # Mostrar vulnerabilidades
        self.vuln_scanner.pretty_print_vulnerabilities(all_vulnerabilities)
        
        # Paso 4: Generar reporte
        if all_vulnerabilities:
            self.vuln_scanner.generate_report(all_vulnerabilities)
        
        # Guardar resultados
        self.results = {
            'services': [s.to_dict() for s in services],
            'vulnerabilities': [v.to_dict() for v in all_vulnerabilities],
            'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'target': target,
            'ports': ports
        }
        
        self._save_results()
        self._print_summary(services, all_vulnerabilities)
        
        return self.results
    
    def _prioritize_services(self, services: List[Dict]) -> List[Dict]:
        """Prioriza servicios para análisis de vulnerabilidades"""
        prioritized = []
        
        for service in services:
            service_name = service['service_name'].lower()
            
            # Servicios comúnmente vulnerables
            vulnerable_keywords = ['ftp', 'telnet', 'http', 'smtp', 'samba', 'apache', 'nginx', 
                                 'mysql', 'postgresql', 'redis', 'elasticsearch', 'vnc', 'rdp']
            
            is_vulnerable_target = any(keyword in service_name for keyword in vulnerable_keywords)
            is_insecure = not service.get('is_secure', False)
            
            # Prioridad alta si es vulnerable y no seguro
            if is_vulnerable_target and is_insecure:
                service['priority'] = 'HIGH'
                prioritized.append(service)
            elif is_vulnerable_target or is_insecure:
                service['priority'] = 'MEDIUM'
                prioritized.append(service)
            else:
                service['priority'] = 'LOW'
                # Puedes comentar esta línea para ignorar servicios de baja prioridad
                prioritized.append(service)
        
        return prioritized
    
    def _save_results(self):
        """Guarda resultados en archivo JSON"""
        filename = f"scan_results_{time.strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.console.print(f"[green]Results saved to {filename}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving results: {e}[/red]")
    
    def _print_summary(self, services: List[ServiceInfo], vulnerabilities: List[Vulnerability]):
        """Imprime resumen ejecutivo del escaneo"""
        summary_panel = Panel.fit(
            f"[bold]SCAN SUMMARY[/bold]\n\n"
            f"Services Found: [cyan]{len(services)}[/cyan]\n"
            f"Vulnerabilities Found: [cyan]{len(vulnerabilities)}[/cyan]\n\n"
            f"Critical Vulnerabilities: [red]{sum(1 for v in vulnerabilities if v.severity == 'CRITICAL')}[/red]\n"
            f"High Vulnerabilities: [yellow]{sum(1 for v in vulnerabilities if v.severity == 'HIGH')}[/yellow]\n"
            f"Insecure Services: [yellow]{sum(1 for s in services if not s.is_secure)}[/yellow]\n\n"
            f"[dim]Results saved to JSON file.[/dim]",
            border_style="green",
            title="Executive Summary"
        )
        
        self.console.print(summary_panel)
    
    def scan_multiple_targets(self, targets: List[str], ports: str = "1-1000"):
        """Escanea múltiples objetivos secuencialmente"""
        all_results = {}
        
        for target in targets:
            self.console.print(f"\n[bold cyan]Scanning target: {target}[/bold cyan]")
            results = self.scan_target(target, ports)
            all_results[target] = results
        
        return all_results

def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Integrated Network and Vulnerability Scanner"
    )
    parser.add_argument(
        "target",
        help="Target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24)"
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="Port range to scan (default: 1-1000)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for results"
    )
    
    args = parser.parse_args()
    
    # Crear y ejecutar escáner
    scanner = IntegratedSecurityScanner()
    
    try:
        results = scanner.scan_target(args.target, args.ports)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {args.output}")
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError during scan: {e}")

if __name__ == "__main__":
    main()
