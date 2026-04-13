class Colors:
    """Códigos ANSI para colores en terminal"""
    
    # Colores básicos
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Colores brillantes
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Estilos
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    
    # Aliases
    SUCCESS = GREEN
    WARNING = YELLOW
    ERROR = RED
    INFO = CYAN
    
    @staticmethod
    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}"
    
    @staticmethod
    def success(text: str) -> str:
        return Colors.colorize(text, Colors.SUCCESS)
    
    @staticmethod
    def warning(text: str) -> str:
        return Colors.colorize(text, Colors.WARNING)
    
    @staticmethod
    def error(text: str) -> str:
        return Colors.colorize(text, Colors.ERROR)
    
    @staticmethod
    def info(text: str) -> str:
        return Colors.colorize(text, Colors.INFO)