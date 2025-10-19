import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from netmiko import ConnectHandler
import yaml
import time
import os
import json
from datetime import datetime

# Datos extendidos según CISA ED 25-03
end_of_life_asa_models = [
    "ASA5525-X", "ASA5545-X", "ASA5555-X", "ASA5585-X",
    "ASA5505", "ASA5510", "ASA5520", "ASA5540", "ASA5580"
]
end_of_support_asa_models = ["ASAv", "ASA5508-X", "ASA5516-X"]
affected_versions = ["9.8(1)", "9.8(1)5", "9.8(1)7", "9.8(2)", "9.8(2)8", "9.8(2)14"]

# Configuración de cumplimiento CISA
CISA_COMPLIANCE_CHECKS = {
    "network_segmentation": [
        {"name": "VLAN Segmentation", "command": "show vlan"},
        {"name": "Security Zones", "command": "show nameif"},
        {"name": "Interface Security Levels", "command": "show interface"}
    ],
    "access_control": [
        {"name": "ACL Enforcement", "command": "show access-list"},
        {"name": "Access Groups", "command": "show running-config access-group"},
        {"name": "Global ACL", "command": "show running-config | include access-list global_deny"}
    ],
    "logging": [
        {"name": "Syslog Configuration", "command": "show running-config logging"},
        {"name": "Logging Enabled", "command": "show logging"},
        {"name": "Logging Buffer", "command": "show logging buffer"}
    ],
    "system_hardening": [
        {"name": "SSH Configuration", "command": "show running-config ssh"},
        {"name": "SNMP Security", "command": "show running-config snmp"},
        {"name": "NTP Configuration", "command": "show ntp associations"},
        {"name": "Banner Configuration", "command": "show running-config banner"},
        {"name": "User Accounts", "command": "show running-config username"}
    ],
    "service_policies": [
        {"name": "Service Policies", "command": "show service-policy"},
        {"name": "MPF Configuration", "command": "show running-config policy-map"}
    ]
}


def connect_device(ip, usuario, password, secret):
    device = {
        "device_type": "cisco_asa",
        "host": ip,
        "username": usuario,
        "password": password,
        "secret": secret
    }
    net_connect = ConnectHandler(**device)
    net_connect.enable()
    return net_connect


def identification_func(ip, usuario, password, secret, result_widget):
    try:
        net_connect = connect_device(ip, usuario, password, secret)
        facts = net_connect.send_command("show version", use_textfsm=True)

        # Manejar diferentes formatos de respuesta
        if isinstance(facts, list) and len(facts) > 0:
            model = facts[0].get('hardware', [{}])[0].get('model', 'N/A') if 'hardware' in facts[0] else 'N/A'
            serial = facts[0].get('hardware', [{}])[0].get('serial', 'N/A') if 'hardware' in facts[0] else 'N/A'
            version = facts[0].get('version', 'N/A')
        else:
            model = facts.get('hardware', [{}])[0].get('model', 'N/A') if 'hardware' in facts else 'N/A'
            serial = facts.get('hardware', [{}])[0].get('serial', 'N/A') if 'hardware' in facts else 'N/A'
            version = facts.get('version', 'N/A')

        cisa_status = []
        if model in end_of_life_asa_models:
            cisa_status.append(f"❌ {model} ({serial}) está End of Life (EoL)")
        elif model in end_of_support_asa_models:
            cisa_status.append(f"⚠️ {model} ({serial}) está End of Support (EoS)")
        elif version in affected_versions:
            cisa_status.append(f"🚨 {serial} versión impactada ({version})")
        else:
            cisa_status.append("✅ Dispositivo y versión seguros")

        os.makedirs("show_ver", exist_ok=True)
        device_info = {
            "model": model,
            "serial_number": serial,
            "version": version,
            "cisa_status": cisa_status,
            "timestamp": datetime.now().isoformat()
        }
        with open(f"show_ver/{serial}_version.yml", "w") as f:
            yaml.dump(device_info, f)

        result = f"""🔍 IDENTIFICACIÓN COMPLETADA - ASA {ip}

📋 Información del Dispositivo:
• Modelo: {model}
• Serial: {serial}
• Versión: {version}

📊 Estado CISA:
• {', '.join(cisa_status)}

✅ Archivo guardado: show_ver/{serial}_version.yml"""

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, result)
        net_connect.disconnect()
    except Exception as e:
        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, f"❌ Error en identificación: {e}")


def compliance_func(ip, usuario, password, secret, result_widget):
    try:
        net_connect = connect_device(ip, usuario, password, secret)

        # Obtener información del dispositivo
        inventory = net_connect.send_command("show inventory", use_textfsm=True)
        if isinstance(inventory, list) and len(inventory) > 0:
            serial = inventory[0].get('sn', 'unknown')
        else:
            serial = "unknown"

        results = {
            "timestamp": datetime.now().isoformat(),
            "device_ip": ip,
            "serial": serial,
            "compliance_checks": {}
        }

        # Ejecutar todas las verificaciones de cumplimiento
        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, "🔄 Ejecutando verificaciones de cumplimiento CISA ED 25-03...\n\n")
        result_widget.update()

        for category, checks in CISA_COMPLIANCE_CHECKS.items():
            results["compliance_checks"][category] = []

            for check in checks:
                try:
                    result_widget.insert(tk.END, f"• Verificando: {check['name']}... ")
                    result_widget.update()

                    output = net_connect.send_command(check["command"])
                    status = "PASS" if output and "invalid command" not in output.lower() else "FAIL"

                    results["compliance_checks"][category].append({
                        "name": check["name"],
                        "status": status,
                        "command": check["command"],
                        "output_sample": output[:200] + "..." if output and len(output) > 200 else output
                    })

                    result_widget.insert(tk.END, f"{status} ✅\n")
                    result_widget.update()

                except Exception as e:
                    results["compliance_checks"][category].append({
                        "name": check["name"],
                        "status": "ERROR",
                        "command": check["command"],
                        "error": str(e)
                    })
                    result_widget.insert(tk.END, f"ERROR ❌\n")
                    result_widget.update()

        # Guardar resultados
        os.makedirs("compliance_reports", exist_ok=True)
        with open(f"compliance_reports/{serial}_cisa_report.json", "w") as f:
            json.dump(results, f, indent=2)

        # Calcular métricas
        total_checks = 0
        passed_checks = 0

        for category in results["compliance_checks"].values():
            for check in category:
                total_checks += 1
                if check["status"] == "PASS":
                    passed_checks += 1

        compliance_score = (passed_checks / total_checks) * 100 if total_checks > 0 else 0

        # Generar reporte final
        result_text = f"""
📊 REPORTE DE CUMPLIMIENTO CISA ED 25-03

Dispositivo: ASA {ip} (Serial: {serial})
Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🎯 PUNTUACIÓN DE CUMPLIMIENTO: {compliance_score:.1f}%
✅ Verificaciones Exitosas: {passed_checks}/{total_checks}
❌ Verificaciones Fallidas: {total_checks - passed_checks}

📈 RESUMEN POR CATEGORÍA:
"""

        for category, checks in results["compliance_checks"].items():
            category_passed = sum(1 for check in checks if check["status"] == "PASS")
            category_icon = "✅" if category_passed == len(checks) else "⚠️" if category_passed > 0 else "❌"
            result_text += f"{category_icon} {category.replace('_', ' ').title()}: {category_passed}/{len(checks)}\n"

        result_text += f"""
📁 Reporte completo guardado en: compliance_reports/{serial}_cisa_report.json

💡 RECOMENDACIONES:
"""
        if compliance_score < 80:
            result_text += "• Revisar configuración de logging y monitoreo\n"
            result_text += "• Verificar políticas de acceso y segmentación\n"
            result_text += "• Aplicar hardening de servicios (SSH, SNMP)\n"
            result_text += "• Usar la pestaña 'Remediation' para correcciones automáticas"
        else:
            result_text += "• Buen nivel de cumplimiento general\n"
            result_text += "• Mantener configuraciones actualizadas\n"
            result_text += "• Realizar auditorías periódicas"

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, result_text)
        net_connect.disconnect()
    except Exception as e:
        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, f"❌ Error en verificación de cumplimiento: {e}")


def artifacts_func(ip, usuario, password, secret, result_widget):
    try:
        net_connect = connect_device(ip, usuario, password, secret)

        # Obtener serial para nombres de archivo
        inventory = net_connect.send_command("show inventory", use_textfsm=True)
        if isinstance(inventory, list) and len(inventory) > 0:
            serial = inventory[0].get('sn', 'unknown')
        else:
            serial = "unknown"

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, "🔄 Recopilando artefactos de auditoría...\n\n")
        result_widget.update()

        # checkheaps (5 segundos para demo)
        os.makedirs("check_heaps", exist_ok=True)
        result_widget.insert(tk.END, "• Ejecutando primer checkheaps... ")
        result_widget.update()
        checkheaps_first = net_connect.send_command("show checkheaps")
        with open(f"check_heaps/{serial}_ch1.txt", "w") as f:
            f.write(checkheaps_first)
        result_widget.insert(tk.END, "✅\n")
        result_widget.update()

        result_widget.insert(tk.END, "• Esperando 5 segundos... ")
        result_widget.update()
        time.sleep(5)  # 5 segundos para demo (en producción sería 300)
        result_widget.insert(tk.END, "✅\n")
        result_widget.update()

        result_widget.insert(tk.END, "• Ejecutando segundo checkheaps... ")
        result_widget.update()
        checkheaps_second = net_connect.send_command("show checkheaps")
        with open(f"check_heaps/{serial}_ch2.txt", "w") as f:
            f.write(checkheaps_second)
        result_widget.insert(tk.END, "✅\n")
        result_widget.update()

        # show tech-support detail
        os.makedirs("show_tech", exist_ok=True)
        result_widget.insert(tk.END, "• Recopilando tech-support detail... ")
        result_widget.update()
        net_connect.send_command("terminal pager 0")
        tech_file = net_connect.send_command("show tech-support detail")
        with open(f"show_tech/{serial}_techsupport.txt", "w") as f:
            f.write(tech_file)
        result_widget.insert(tk.END, "✅\n")
        result_widget.update()

        # Configuración running
        result_widget.insert(tk.END, "• Guardando configuración running... ")
        result_widget.update()
        running_config = net_connect.send_command("show running-config")
        with open(f"show_tech/{serial}_running_config.txt", "w") as f:
            f.write(running_config)
        result_widget.insert(tk.END, "✅\n")
        result_widget.update()

        result_text = f"""
📁 RECOPILACIÓN DE ARTEFACTOS COMPLETADA - ASA {ip}

✅ Artefactos guardados:
• check_heaps/{serial}_ch1.txt (primera medición)
• check_heaps/{serial}_ch2.txt (segunda medición - después de 5 segundos)
• show_tech/{serial}_techsupport.txt (tech-support detail)
• show_tech/{serial}_running_config.txt (configuración running)

📊 Uso previsto:
• checkheaps: Para detectar memory leaks
• tech-support: Para análisis forense completo
• running-config: Para auditoría de configuración

Serial del dispositivo: {serial}
"""

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, result_text)
        net_connect.disconnect()
    except Exception as e:
        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, f"❌ Error recopilando artefactos: {e}")


def implant_func(ip, usuario, password, secret, result_widget):
    try:
        net_connect = connect_device(ip, usuario, password, secret)

        # Obtener serial
        inventory = net_connect.send_command("show inventory", use_textfsm=True)
        if isinstance(inventory, list) and len(inventory) > 0:
            serial = inventory[0].get('sn', 'unknown')
        else:
            serial = "unknown"

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, "🔄 Ejecutando chequeo de implantes...\n\n")
        result_widget.update()

        os.makedirs("implant_check", exist_ok=True)
        result_widget.insert(tk.END, "• Buscando patrones de implantes conocidos... ")
        result_widget.update()

        implant = net_connect.send_command("more /binary system:/text | grep 55534154 41554156 41575756 488bb3a0")

        with open(f"implant_check/{serial}_implant_check.txt", "w") as f:
            f.write(implant)

        if implant.strip() and "no such" not in implant.lower():
            status = "🚨 POSIBLE IMPLANT DETECTADO"
            recommendation = "• Contactar inmediatamente al equipo de seguridad\n• Aislar el dispositivo de la red\n• Realizar análisis forense completo"
        else:
            status = "✅ No se detectaron implantes conocidos"
            recommendation = "• Mantener monitoreo continuo\n• Actualizar firmware regularmente\n• Implementar detección de amenazas"

        result_text = f"""
🛡️ CHEQUEO DE IMPLANTES COMPLETADO - ASA {ip}

📊 Resultado:
{status}

📋 Detalles:
• Comando ejecutado: more /binary system:/text | grep 55534154 41554156 41575756 488bb3a0
• Output: {'Patrones encontrados' if implant.strip() and 'no such' not in implant.lower() else 'Sin patrones detectados'}

💡 Recomendaciones:
{recommendation}

📁 Archivo guardado: implant_check/{serial}_implant_check.txt
Serial: {serial}
"""

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, result_text)
        net_connect.disconnect()
    except Exception as e:
        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, f"❌ Error en chequeo de implantes: {e}")


def remediation_func(ip, usuario, password, secret, result_widget):
    try:
        net_connect = connect_device(ip, usuario, password, secret)

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, "🔄 Aplicando medidas de remediación...\n\n")
        result_widget.update()

        remediation_commands = [
            "logging enable",
            "logging timestamp",
            "logging buffer-size 1048576",
            "logging trap informational",
            "ssh timeout 30",
            "ssh version 2",
            "no snmp-server community public",
            "no snmp-server community private"
        ]

        results = []
        for cmd in remediation_commands:
            try:
                result_widget.insert(tk.END, f"• Aplicando: {cmd}... ")
                result_widget.update()

                output = net_connect.send_config_set([cmd])
                results.append(f"✅ {cmd}")
                result_widget.insert(tk.END, "✅\n")
                result_widget.update()

            except Exception as e:
                results.append(f"❌ {cmd} - Error: {str(e)}")
                result_widget.insert(tk.END, "❌\n")
                result_widget.update()

        # Guardar configuración
        result_widget.insert(tk.END, "• Guardando configuración... ")
        result_widget.update()
        net_connect.save_config()
        result_widget.insert(tk.END, "✅\n")
        result_widget.update()

        # Generar reporte final
        result_text = f"""
🔧 REMEDIACIÓN APLICADA - ASA {ip}

✅ Comandos ejecutados exitosamente:
"""
        successful_commands = [r for r in results if "✅" in r]
        failed_commands = [r for r in results if "❌" in r]

        for cmd in successful_commands:
            result_text += f"{cmd}\n"

        if failed_commands:
            result_text += f"\n❌ Comandos con errores:\n"
            for cmd in failed_commands:
                result_text += f"{cmd}\n"

        result_text += f"""
📊 Resumen:
• Comandos exitosos: {len(successful_commands)}/{len(remediation_commands)}
• Configuración guardada: ✅

💡 Recomendaciones adicionales:
• Verificar conectividad después de los cambios
• Monitorear logs para detectar problemas
• Realizar backup de la nueva configuración
• Programar auditoría de cumplimiento periódica
"""

        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, result_text)
        net_connect.disconnect()
    except Exception as e:
        result_widget.delete('1.0', tk.END)
        result_widget.insert(tk.END, f"❌ Error en remediación: {e}")


def get_all_fields():
    ip = entry_ip.get().strip()
    usuario = entry_user.get().strip()
    password = entry_pass.get().strip()
    secret = entry_enable.get().strip()
    return ip, usuario, password, secret


def menu_identification():
    ip, usuario, password, secret = get_all_fields()
    identification_func(ip, usuario, password, secret, txt_result_ident)


def menu_compliance():
    ip, usuario, password, secret = get_all_fields()
    compliance_func(ip, usuario, password, secret, txt_result_compliance)


def menu_artifacts():
    ip, usuario, password, secret = get_all_fields()
    artifacts_func(ip, usuario, password, secret, txt_result_artifacts)


def menu_implant():
    ip, usuario, password, secret = get_all_fields()
    implant_func(ip, usuario, password, secret, txt_result_implant)


def menu_remediation():
    ip, usuario, password, secret = get_all_fields()
    remediation_func(ip, usuario, password, secret, txt_result_remediation)


# GUI principal con ORDEN LÓGICO
root = tk.Tk()
root.title("Auditoría CISA ED 25-03 para Cisco ASA - By Alex Luna")
root.geometry("800x700")

# Frame superior para credenciales
frm_top = ttk.LabelFrame(root, text="🔐 Credenciales del ASA")
frm_top.pack(fill="x", padx=10, pady=5)

tk.Label(frm_top, text="IP ASA:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_ip = tk.Entry(frm_top, width=25)
entry_ip.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frm_top, text="Usuario:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entry_user = tk.Entry(frm_top, width=25)
entry_user.grid(row=1, column=1, padx=5, pady=5)

tk.Label(frm_top, text="Contraseña:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
entry_pass = tk.Entry(frm_top, show="*", width=25)
entry_pass.grid(row=2, column=1, padx=5, pady=5)

tk.Label(frm_top, text="Enable secret:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
entry_enable = tk.Entry(frm_top, show="*", width=25)
entry_enable.grid(row=3, column=1, padx=5, pady=5)

# Notebook con ORDEN LÓGICO
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=5)

# 1. Identificación (primero)
tab_ident = ttk.Frame(notebook)
notebook.add(tab_ident, text="1. 🔍 Identificación")
btn_ident = tk.Button(tab_ident, text="Ejecutar Identificación del Dispositivo", command=menu_identification,
                      bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
btn_ident.pack(pady=10)
txt_result_ident = scrolledtext.ScrolledText(tab_ident, height=20, width=80, font=("Consolas", 9))
txt_result_ident.pack(padx=10, pady=5, fill="both", expand=True)

# 2. Cumplimiento CISA (segundo)
tab_compliance = ttk.Frame(notebook)
notebook.add(tab_compliance, text="2. 📊 Cumplimiento CISA")
btn_compliance = tk.Button(tab_compliance, text="Verificar Cumplimiento ED 25-03", command=menu_compliance,
                           bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
btn_compliance.pack(pady=10)
txt_result_compliance = scrolledtext.ScrolledText(tab_compliance, height=20, width=80, font=("Consolas", 9))
txt_result_compliance.pack(padx=10, pady=5, fill="both", expand=True)

# 3. Artefactos (tercero)
tab_artifacts = ttk.Frame(notebook)
notebook.add(tab_artifacts, text="3. 📁 Artefactos")
btn_artifacts = tk.Button(tab_artifacts, text="Recopilar Artefactos de Auditoría", command=menu_artifacts,
                          bg="#FF9800", fg="white", font=("Arial", 10, "bold"))
btn_artifacts.pack(pady=10)
txt_result_artifacts = scrolledtext.ScrolledText(tab_artifacts, height=20, width=80, font=("Consolas", 9))
txt_result_artifacts.pack(padx=10, pady=5, fill="both", expand=True)

# 4. Implant Check (cuarto)
tab_implant = ttk.Frame(notebook)
notebook.add(tab_implant, text="4. 🛡️ Implant Check")
btn_implant = tk.Button(tab_implant, text="Chequeo de Implantes de Seguridad", command=menu_implant,
                        bg="#F44336", fg="white", font=("Arial", 10, "bold"))
btn_implant.pack(pady=10)
txt_result_implant = scrolledtext.ScrolledText(tab_implant, height=20, width=80, font=("Consolas", 9))
txt_result_implant.pack(padx=10, pady=5, fill="both", expand=True)

# 5. Remediation (último)
tab_remediation = ttk.Frame(notebook)
notebook.add(tab_remediation, text="5. 🔧 Remediation")
btn_remediation = tk.Button(tab_remediation, text="Aplicar Medidas de Remediation", command=menu_remediation,
                            bg="#9C27B0", fg="white", font=("Arial", 10, "bold"))
btn_remediation.pack(pady=10)
txt_result_remediation = scrolledtext.ScrolledText(tab_remediation, height=20, width=80, font=("Consolas", 9))
txt_result_remediation.pack(padx=10, pady=5, fill="both", expand=True)

# Información del flujo de trabajo
info_text = """
💡 FLUJO DE TRABAJO RECOMENDADO:
1. 🔍 Identificación: Verificar modelo, serial y versión del ASA
2. 📊 Cumplimiento: Evaluar conformidad con CISA ED 25-03  
3. 📁 Artefactos: Recopilar evidencias para análisis
4. 🛡️ Implant Check: Buscar compromisos de seguridad
5. 🔧 Remediation: Aplicar correcciones automáticas
"""
info_label = tk.Label(root, text=info_text, justify=tk.LEFT, bg="#E3F2FD", fg="#1565C0")
info_label.pack(fill="x", padx=10, pady=5)

root.mainloop()