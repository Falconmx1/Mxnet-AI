#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mxnet AI - Herramienta de prueba de red con IA + Nmap
Autor: Falconmx1
Version: 1.0
"""

import argparse
import sys
import os
import subprocess
import json
from datetime import datetime

# Colores para terminal (soporte Windows/Linux)
class Colors:
    if sys.platform == "win32":
        os.system("color")
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def banner():
    """Muestra el banner de Mxnet AI"""
    banner_text = f"""
{Colors.CYAN}{Colors.BOLD}  ╔════════════════════════════════════════╗
  ║        🛡️  MXNET AI v1.0  🛡️          ║
  ║     Red Teaming con Inteligencia       ║
  ║         Artificial + Nmap              ║
  ╚════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner_text)

def verificar_nmap():
    """Verifica que Nmap esté instalado en el sistema"""
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.RED}[!] Nmap no encontrado.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Instalación recomendada:{Colors.RESET}")
        if sys.platform == "win32":
            print("    Descarga desde: https://nmap.org/download.html")
            print("    Luego agrégalo al PATH o coloca nmap.exe en la misma carpeta.")
        else:
            print("    sudo apt install nmap   (Debian/Ubuntu)")
            print("    sudo dnf install nmap   (Fedora)")
        return False

def escanear_con_nmap(target, scan_type="quick"):
    """
    Ejecuta Nmap según el tipo de escaneo.
    Retorna el resultado en XML para parsear.
    """
    print(f"{Colors.BLUE}[*] Iniciando escaneo Nmap sobre {target}...{Colors.RESET}")
    
    # Configuración de escaneo
    scan_options = {
        "quick": "-F",  # Escaneo rápido (puertos comunes)
        "full": "-p-",  # Todos los puertos (65535)
        "common": "-p 1-1000",  # Puertos 1-1000
        "os": "-O",     # Detección de OS
        "script": "-sC -sV"  # Scripts por defecto + versiones
    }
    
    option = scan_options.get(scan_type, "-F")
    output_xml = f"scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    
    cmd = ["nmap", option, "-sS", "-sV", "--script=banner", "-oX", output_xml, target]
    
    try:
        print(f"{Colors.YELLOW}[>] Ejecutando: {' '.join(cmd)}{Colors.RESET}")
        subprocess.run(cmd, check=True)
        print(f"{Colors.GREEN}[✓] Escaneo completado. Resultado guardado en {output_xml}{Colors.RESET}")
        return output_xml
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}[✗] Error en escaneo: {e}{Colors.RESET}")
        return None

def parsear_resultados_nmap(xml_file):
    """Parsea el XML de Nmap y extrae puertos abiertos, servicios, etc."""
    import xml.etree.ElementTree as ET
    
    if not xml_file or not os.path.exists(xml_file):
        return None
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        resultados = {
            "target": "",
            "host_status": "",
            "puertos_abiertos": [],
            "servicios": [],
            "os_guess": None
        }
        
        # Extraer información del host
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None:
                resultados["host_status"] = status.get('state', 'unknown')
            
            # Dirección IP
            addr = host.find('address')
            if addr is not None:
                resultados["target"] = addr.get('addr', '')
            
            # Puertos abiertos y servicios
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open':
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        resultados["puertos_abiertos"].append(port_id)
                        resultados["servicios"].append({
                            "puerto": port_id,
                            "servicio": service_name,
                            "producto": service.get('product', ''),
                            "version": service.get('version', '')
                        })
            
            # Sistema operativo (guess)
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    resultados["os_guess"] = osmatch.get('name', '')
        
        return resultados
    except Exception as e:
        print(f"{Colors.RED}[!] Error parseando XML: {e}{Colors.RESET}")
        return None

def generar_recomendaciones_ia(puertos_abiertos, servicios):
    """Genera recomendaciones basadas en IA simulada o usando API real."""
    # Modelo de recomendaciones por puerto/servicio (IA simulada)
    recomendaciones_db = {
        "22": "⚠️ SSH expuesto. Usa autenticación por clave y cambia el puerto por defecto.",
        "80": "🌐 HTTP visible. Considera implementar HTTPS y WAF.",
        "443": "🔒 HTTPS detectado. Verifica certificados TLS y deshabilita protocolos débiles.",
        "21": "📁 FTP no seguro. Migra a SFTP/FTPS y aplica políticas de acceso.",
        "3306": "🗄️ MySQL/MariaDB expuesto. Limita IPs de conexión y usa contraseñas fuertes.",
        "3389": "💻 RDP abierto. Usa VPN y habilita NLA (Network Level Authentication).",
        "445": "📂 SMB. Riesgo de EternalBlue. Parchea o bloquea si no es necesario.",
        "23": "📟 Telnet inseguro. Deshabilita y usa SSH.",
        "25": "📧 SMTP. Evita open relay y aplica SPF/DKIM.",
        "1433": "📊 MSSQL. Cambia puerto por defecto y aplica autenticación fuerte.",
        "5900": "🖥️ VNC. Usa túneles SSH o cambia por RDP con seguridad.",
        "6379": "⚡ Redis. Añade autenticación y restringe accesos."
    }
    
    recomendaciones = []
    puertos_vistos = set()
    
    for servicio in servicios:
        puerto = servicio["puerto"]
        if puerto in puertos_vistos:
            continue
        puertos_vistos.add(puerto)
        
        # Buscar recomendación específica
        rec = recomendaciones_db.get(puerto)
        if rec:
            recomendaciones.append(f"Puerto {puerto}: {rec}")
        else:
            # Recomendación genérica para otros puertos
            if servicio["servicio"] != "unknown":
                recomendaciones.append(f"Puerto {puerto} ({servicio['servicio']}): Revisa que esté actualizado y con acceso restringido.")
    
    # Agregar recomendaciones generales
    if len(puertos_abiertos) > 10:
        recomendaciones.append("📢 Muchos puertos abiertos. Considera usar un firewall para reducir superficie de ataque.")
    
    if any(p in puertos_abiertos for p in ["21", "23", "3389", "445"]):
        recomendaciones.append("🚨 Servicios de alto riesgo expuestos. Revisa políticas de seguridad urgentemente.")
    
    return recomendaciones if recomendaciones else ["✅ No se encontraron recomendaciones específicas. El sistema parece bien configurado."]

def generar_reporte(resultados, recomendaciones, target, scan_type):
    """Genera reporte en TXT y opcionalmente HTML."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reporte_txt = f"reporte_{target.replace('.', '_')}.txt"
    
    with open(reporte_txt, "w", encoding="utf-8") as f:
        f.write(f"MXNET AI - REPORTE DE SEGURIDAD\n")
        f.write(f"===============================\n")
        f.write(f"Objetivo: {target}\n")
        f.write(f"Tipo de escaneo: {scan_type}\n")
        f.write(f"Fecha: {timestamp}\n\n")
        
        f.write("RESULTADOS DEL ESCANEO:\n")
        f.write(f"Estado del host: {resultados['host_status']}\n")
        if resultados['os_guess']:
            f.write(f"Sistema operativo estimado: {resultados['os_guess']}\n")
        f.write(f"Puertos abiertos: {', '.join(resultados['puertos_abiertos']) if resultados['puertos_abiertos'] else 'Ninguno'}\n\n")
        
        f.write("DETALLE DE SERVICIOS:\n")
        for svc in resultados['servicios']:
            f.write(f"  Puerto {svc['puerto']}: {svc['servicio']} - {svc['producto']} {svc['version']}\n".strip())
        
        f.write("\nRECOMENDACIONES DE IA:\n")
        for rec in recomendaciones:
            f.write(f"  • {rec}\n")
        
        f.write("\n--- Fin del reporte ---\n")
    
    print(f"{Colors.GREEN}[✓] Reporte generado: {reporte_txt}{Colors.RESET}")
    
    # Mostrar resumen en consola
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== RECOMENDACIONES DE IA ==={Colors.RESET}")
    for rec in recomendaciones:
        print(f"  {rec}")
    
    return reporte_txt

def main():
    parser = argparse.ArgumentParser(description="Mxnet AI - Herramienta de pentesting con IA y Nmap")
    parser.add_argument("--target", "-t", required=True, help="IP o dominio objetivo")
    parser.add_argument("--scan-type", "-s", choices=["quick", "full", "common", "os", "script"], 
                        default="quick", help="Tipo de escaneo (default: quick)")
    parser.add_argument("--no-ai", action="store_true", help="Desactiva recomendaciones IA")
    
    args = parser.parse_args()
    
    # Mostrar banner
    banner()
    
    # Verificar Nmap
    if not verificar_nmap():
        sys.exit(1)
    
    # Ejecutar escaneo Nmap
    xml_output = escanear_con_nmap(args.target, args.scan_type)
    if not xml_output:
        sys.exit(1)
    
    # Parsear resultados
    resultados = parsear_resultados_nmap(xml_output)
    if not resultados or not resultados["puertos_abiertos"]:
        print(f"{Colors.YELLOW}[!] No se encontraron puertos abiertos o el host no responde.{Colors.RESET}")
        sys.exit(0)
    
    print(f"\n{Colors.GREEN}[✓] Puertos abiertos encontrados: {', '.join(resultados['puertos_abiertos'])}{Colors.RESET}\n")
    
    # Generar recomendaciones IA
    recomendaciones = []
    if not args.no_ai:
        recomendaciones = generar_recomendaciones_ia(resultados["puertos_abiertos"], resultados["servicios"])
    else:
        recomendaciones = ["Recomendaciones IA desactivadas por el usuario."]
    
    # Generar reporte
    generar_reporte(resultados, recomendaciones, args.target, args.scan_type)
    
    # Limpieza opcional (borrar XML temporal)
    # os.remove(xml_output) # Descomentar si no quieres conservar el XML
    
if __name__ == "__main__":
    main()
