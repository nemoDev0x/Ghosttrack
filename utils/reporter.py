import json
import os
from datetime import datetime
from pathlib import Path
import re
from typing import Dict, Any

class Reporter:
    """Generación de reportes en múltiples formatos"""
    
    def __init__(self, output_dir='reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate(self, target: str, results: Dict, scan_type: str):
        """Genera reportes en todos los formatos"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{self._sanitize_filename(target)}_{scan_type}_{timestamp}"
        
        # JSON
        json_file = self.generate_json(base_name, results)
        
        # HTML
        html_file = self.generate_html(base_name, target, results, scan_type)
        
        # TXT
        txt_file = self.generate_txt(base_name, target, results, scan_type)
        
        print(f"[+] Reportes generados:")
        print(f"    - JSON: {json_file}")
        print(f"    - HTML: {html_file}")
        print(f"    - TXT:  {txt_file}")
        
        return {
            'json': str(json_file),
            'html': str(html_file),
            'txt': str(txt_file)
        }
    
    def generate_json(self, base_name: str, results: Dict) -> Path:
        """Genera reporte JSON"""
        file_path = self.output_dir / f"{base_name}.json"
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False, default=str)
        
        return file_path
    
    def generate_html(self, base_name: str, target: str, results: Dict, scan_type: str) -> Path:
        """Genera reporte HTML"""
        file_path = self.output_dir / f"{base_name}.html"
        
        html_content = self._create_html_report(target, results, scan_type)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return file_path
    
    def generate_txt(self, base_name: str, target: str, results: Dict, scan_type: str) -> Path:
        """Genera reporte TXT"""
        file_path = self.output_dir / f"{base_name}.txt"
        
        txt_content = self._create_txt_report(target, results, scan_type)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(txt_content)
        
        return file_path
    
    def generate_redteam(self, target: str, results: Dict, domain: str = None):
        """Genera reporte específico para Red Team"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{self._sanitize_filename(target)}_redteam_{timestamp}"
        
        return self.generate(target, results, 'redteam')
    
    def _create_html_report(self, target: str, results: Dict, scan_type: str) -> str:
        """Crea contenido HTML del reporte"""
        timestamp = results.get('timestamp', datetime.now().isoformat())
        modules = results.get('modules', {})
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostTrack Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
               background: #0a0e27; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                 padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        h1 {{ font-size: 2.5em; color: white; margin-bottom: 10px; }}
        .subtitle {{ color: #f0f0f0; font-size: 1.1em; }}
        .info-box {{ background: #1a1f3a; padding: 20px; border-radius: 8px; 
                    margin-bottom: 20px; border-left: 4px solid #667eea; }}
        .info-box h3 {{ color: #667eea; margin-bottom: 15px; }}
        .info-item {{ display: flex; justify-content: space-between; 
                     padding: 8px 0; border-bottom: 1px solid #2a2f4a; }}
        .info-label {{ color: #8b8b8b; }}
        .info-value {{ color: #e0e0e0; font-weight: bold; }}
        .module-section {{ background: #1a1f3a; padding: 25px; 
                          border-radius: 8px; margin-bottom: 25px; }}
        .module-section h2 {{ color: #667eea; margin-bottom: 20px; 
                             border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .finding {{ background: #242940; padding: 15px; border-radius: 5px; 
                   margin: 10px 0; border-left: 3px solid #4CAF50; }}
        .finding.high {{ border-left-color: #f44336; }}
        .finding.medium {{ border-left-color: #ff9800; }}
        .finding.low {{ border-left-color: #4CAF50; }}
        .tag {{ display: inline-block; padding: 4px 12px; border-radius: 12px; 
               font-size: 0.85em; margin: 2px; }}
        .tag.critical {{ background: #f44336; color: white; }}
        .tag.high {{ background: #ff9800; color: white; }}
        .tag.medium {{ background: #ffc107; color: black; }}
        .tag.low {{ background: #4CAF50; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background: #2a2f4a; padding: 12px; text-align: left; color: #667eea; }}
        td {{ padding: 12px; border-bottom: 1px solid #2a2f4a; }}
        tr:hover {{ background: #242940; }}
        code {{ background: #2a2f4a; padding: 2px 6px; border-radius: 3px; 
               color: #00ff00; font-family: 'Courier New', monospace; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; 
                  color: #8b8b8b; border-top: 1px solid #2a2f4a; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>GhostTrack Security Report</h1>
            <div class="subtitle">Advanced Pentesting Framework</div>
        </header>
        
        <div class="info-box">
            <h3>Información del Escaneo</h3>
            <div class="info-item">
                <span class="info-label">Target:</span>
                <span class="info-value">{target}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Tipo de Escaneo:</span>
                <span class="info-value">{scan_type.upper()}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Fecha:</span>
                <span class="info-value">{timestamp}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Módulos Ejecutados:</span>
                <span class="info-value">{len(modules)}</span>
            </div>
        </div>
        
        <div class="module-section">
            <h2>Resultados de Módulos</h2>
"""
        
        # Añadir resultados de cada módulo
        for module_name, module_data in modules.items():
            html += f"""
            <div class="finding">
                <h3>{module_name.replace('_', ' ').title()}</h3>
                <pre style="background: #0a0e27; padding: 15px; border-radius: 5px; overflow-x: auto;">
{json.dumps(module_data, indent=2, default=str)}
                </pre>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>Generado por GhostTrack v2.0 | Framework de Pentesting</p>
            <p>Este reporte contiene información sensible - Manéjelo con cuidado</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def _create_txt_report(self, target: str, results: Dict, scan_type: str) -> str:
        """Crea contenido TXT del reporte"""
        timestamp = results.get('timestamp', datetime.now().isoformat())
        modules = results.get('modules', {})
        
        txt = f"""
═══════════════════════════════════════════════════════════════════
                    GHOSTTRACK SECURITY REPORT
═══════════════════════════════════════════════════════════════════

Target:         {target}
Scan Type:      {scan_type.upper()}
Date:           {timestamp}
Modules:        {len(modules)}

═══════════════════════════════════════════════════════════════════
                         MODULE RESULTS
═══════════════════════════════════════════════════════════════════

"""
        
        for module_name, module_data in modules.items():
            txt += f"\n{'─' * 70}\n"
            txt += f"MODULE: {module_name.upper()}\n"
            txt += f"{'─' * 70}\n"
            txt += json.dumps(module_data, indent=2, default=str)
            txt += "\n"
        
        txt += f"""
═══════════════════════════════════════════════════════════════════
                              FOOTER
═══════════════════════════════════════════════════════════════════

Generated by: GhostTrack v2.0
Framework:    Advanced Pentesting & Red Team
Warning:      This report contains sensitive information

═══════════════════════════════════════════════════════════════════
"""
        
        return txt
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitiza nombre de archivo"""
        return re.sub(r'[<>:"/\\|?*]', '_', filename)
