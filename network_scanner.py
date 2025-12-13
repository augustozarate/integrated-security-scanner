import socket
import nmap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import json
import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

@dataclass
class ServiceInfo:
    """Clase para almacenar información de servicios detectados"""
    ip: str
    port: int
    service_name: str
    banner: str = ""
    version: str = ""
    product: str = ""
    protocol: str = "tcp"
    is_secure: bool = False
    
    def to_dict(self) -> Dict:
        """Convierte a diccionario para serialización"""
        return {
            'ip': self.ip,
            'port': self.port,
            'service_name': self.service_name,
            'banner': self.banner,
            'version': self.version,
            'protocol': self.protocol,
            'is_secure': self.is_secure
        }

class NetworkScanner:
    """Escáner de red con detección de servicios y banners"""
    
    def __init__(self, max_threads: int = 50, timeout: float = 2.0):
        self.max_threads = max_threads
        self.timeout = timeout
        self.nm = nmap.PortScanner()
        self.console = Console()
        self.cache_file = "scan_cache.json"
        self.scan_cache = self._load_cache()
        
    def _load_cache(self) -> Dict:
        """Carga resultados de escaneos previos desde caché"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_cache(self):
        """Guarda resultados en caché"""
        try:
            cache_copy = self.scan_cache.copy()
            with open(self.cache_file, 'w') as f:
                json.dump(cache_copy, f, indent=2)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not save cache: {e}[/yellow]")
    
    def _get_cache_key(self, target: str, ports: str) -> str:
        """Genera clave única para caché"""
        return f"{target}:{ports}"
    
    def scan_network(self, target: str, ports: str = "1-1000") -> List[ServiceInfo]:
        """
        Escanea una red o host específico y detecta servicios
        
        Args:
            target: Dirección IP o rango (ej: '192.168.1.0/24' o '192.168.1.1')
            ports: Rango de puertos a escanear (ej: '1-1000', '22,80,443')
        
        Returns:
            Lista de servicios detectados
        """
        cache_key = self._get_cache_key(target, ports)
        
        # Verificar caché
        if cache_key in self.scan_cache:
            self.console.print(f"[green]Using cached results for {target}[/green]")
            cached_data = self.scan_cache[cache_key]
            return [ServiceInfo(**data) for data in cached_data]
        
        self.console.print(f"[cyan]Scanning {target} on ports {ports}...[/cyan]")
        
        services_found = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task("Scanning network...", total=None)
            
            try:
                # Escaneo inicial con nmap
                self.nm.scan(hosts=target, ports=ports, arguments='-sV --open')
                
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        for proto in self.nm[host].all_protocols():
                            ports_info = self.nm[host][proto].keys()
                            
                            for port in ports_info:
                                port_info = self.nm[host][proto][port]
                                
                                service = ServiceInfo(
                                    ip=host,
                                    port=port,
                                    service_name=port_info.get('name', 'unknown'),
                                    version=port_info.get('version', ''),
                                    product=port_info.get('product', ''),
                                    protocol=proto
                                )
                                
                                # Intentar obtener banner adicional
                                banner = self._get_banner(host, port)
                                if banner:
                                    service.banner = banner
                                    
                                    # Detectar si es servicio seguro
                                    service.is_secure = any(secure in banner.lower() or secure in service.service_name.lower() 
                                                          for secure in ['ssl', 'tls', 'https', 'ssh'])
                                
                                services_found.append(service)
            
            except Exception as e:
                self.console.print(f"[red]Error during scan: {e}[/red]")
                return services_found
        
        # Guardar en caché
        self.scan_cache[cache_key] = [s.to_dict() for s in services_found]
        self._save_cache()
        
        return services_found
    
    def _get_banner(self, ip: str, port: int) -> str:
        """Intenta obtener el banner de un servicio"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5) # O self.timeout
            sock.connect((ip, port))
            
            # Enviar solicitud básica para algunos servicios comunes
            if port == 80:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                sock.send(b"")
            elif port == 22:
                sock.send(b"SSH-2.0-Client\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Limpiar banner
            banner_lines = banner.split('\n')
            if banner_lines:
                return banner_lines[0][:100]  # Primera línea, máximo 100 chars
            
        except:
            return ""
    
    def scan_single_host(self, ip: str) -> List[ServiceInfo]:
        """Escanea un solo host para servicios comunes"""
        common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
        return self.scan_network(ip, common_ports)
    
    def scan_multiple_hosts(self, ip_list: List[str]) -> Dict[str, List[ServiceInfo]]:
        """Escanea múltiples hosts en paralelo"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ip_list))) as executor:
            future_to_ip = {executor.submit(self.scan_single_host, ip): ip for ip in ip_list}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception as e:
                    self.console.print(f"[red]Error scanning {ip}: {e}[/red]")
                    results[ip] = []
        
        return results
    
    def get_service_summary(self, services: List[ServiceInfo]) -> Dict:
        """Genera un resumen estadístico de los servicios encontrados"""
        summary = {
            'total_services': len(services),
            'unique_ips': len(set(s.ip for s in services)),
            'service_counts': {},
            'port_counts': {},
            'insecure_services': 0,
            'common_vulnerable_services': []
        }
        
        vulnerable_services = ['ftp', 'telnet', 'http', 'smtp', 'vnc', 'rdp']
        
        for service in services:
            # Contar servicios por nombre
            service_name = service.service_name.lower()
            summary['service_counts'][service_name] = summary['service_counts'].get(service_name, 0) + 1
            
            # Contar puertos
            summary['port_counts'][service.port] = summary['port_counts'].get(service.port, 0) + 1
            
            # Servicios inseguros
            if not service.is_secure:
                summary['insecure_services'] += 1
            
            # Servicios comúnmente vulnerables
            if any(vs in service_name for vs in vulnerable_services) and not service.is_secure:
                summary['common_vulnerable_services'].append(service)
        
        return summary
    
    def pretty_print_services(self, services: List[ServiceInfo]):
        """Muestra los servicios encontrados en formato tabla"""
        if not services:
            self.console.print("[yellow]No services found.[/yellow]")
            return
        
        table = Table(title="Network Services Found")
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Port", style="green")
        table.add_column("Service", style="magenta")
        table.add_column("Version", style="yellow")
        table.add_column("Banner", style="white")
        table.add_column("Secure", style="red")
        
        for service in sorted(services, key=lambda x: (x.ip, x.port)):
            secure_text = "[green]✓[/green]" if service.is_secure else "[red]✗[/red]"
            banner_short = service.banner[:30] + "..." if len(service.banner) > 30 else service.banner
            
            table.add_row(
                service.ip,
                str(service.port),
                service.service_name,
                service.version,
                banner_short,
                secure_text
            )
        
        self.console.print(table)
        
        # Mostrar estadísticas
        summary = self.get_service_summary(services)
        self.console.print(f"\n[cyan]Summary:[/cyan]")
        self.console.print(f"  • Total services: {summary['total_services']}")
        self.console.print(f"  • Unique hosts: {summary['unique_ips']}")
        self.console.print(f"  • Insecure services: {summary['insecure_services']}")
        
        if summary['common_vulnerable_services']:
            self.console.print(f"\n[yellow]Potentially vulnerable services found:[/yellow]")
            for service in summary['common_vulnerable_services'][:5]:  # Mostrar solo 5
                self.console.print(f"  • {service.ip}:{service.port} - {service.service_name}")