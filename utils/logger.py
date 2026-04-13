import logging
import os
from datetime import datetime
from pathlib import Path

class Logger:
    """Sistema de logging para GhostTrack"""
    
    def __init__(self, log_dir='logs', log_file=None):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        if not log_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = f'ghosttrack_{timestamp}.log'
        
        self.log_file = self.log_dir / log_file
        
        # Configurar logger
        self.logger = logging.getLogger('GhostTrack')
        self.logger.setLevel(logging.DEBUG)
        
        # Handler para archivo
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Handler para consola
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formato
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Añadir handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
    def debug(self, message):
        self.logger.debug(message)
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def log_scan_start(self, target, scan_type):
        self.info(f"Iniciando {scan_type} scan en {target}")
    
    def log_scan_end(self, target, scan_type, duration):
        self.info(f"Finalizado {scan_type} scan en {target} (duración: {duration}s)")
    
    def log_module_execution(self, module_name, target, status):
        self.info(f"Módulo {module_name} en {target}: {status}")
    
    def log_vulnerability_found(self, vuln_type, target, severity):
        self.warning(f"Vulnerabilidad encontrada: {vuln_type} en {target} (Severidad: {severity})")
