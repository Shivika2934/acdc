import os
import shutil
import sys
import platform
from datetime import datetime
from typing import Optional

# ANSI escape codes for colors
class Colors:
    # Background colors
    BG_BLUE = '\033[44m' if platform.system() != 'Windows' else ''
    BG_DARK_BLUE = '\033[48;5;17m' if platform.system() != 'Windows' else ''
    BG_BLACK = '\033[40m' if platform.system() != 'Windows' else ''
    
    # Foreground colors
    HEADER = '\033[95m' if platform.system() != 'Windows' else ''
    BLUE = '\033[94m' if platform.system() != 'Windows' else ''
    CYAN = '\033[96m' if platform.system() != 'Windows' else ''
    GREEN = '\033[92m' if platform.system() != 'Windows' else ''
    WARNING = '\033[93m' if platform.system() != 'Windows' else ''
    FAIL = '\033[91m' if platform.system() != 'Windows' else ''
    
    # Styles
    BOLD = '\033[1m' if platform.system() != 'Windows' else ''
    UNDERLINE = '\033[4m' if platform.system() != 'Windows' else ''
    ENDC = '\033[0m' if platform.system() != 'Windows' else ''

# Web UI Color Constants
class WebColors:
    # Gradients
    PRIMARY_GRADIENT = 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)'
    SECONDARY_GRADIENT = 'linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)'
    SUCCESS_GRADIENT = 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
    WARNING_GRADIENT = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)'
    DANGER_GRADIENT = 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)'
    
    # Backgrounds
    DARK_BG = '#0f172a'
    CARD_BG = '#1e293b'
    CARD_BORDER = '#334155'
    
    # Text colors
    TEXT_PRIMARY = '#f8fafc'
    TEXT_SECONDARY = '#cbd5e1'
    TEXT_MUTED = '#64748b'

def setup_console():
    """Setup console for color support on Windows"""
    if platform.system() == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            os.system('color')
        except:
            pass

def clear_screen():
    """Clear console screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def get_terminal_size():
    """Get terminal dimensions"""
    return shutil.get_terminal_size()

def print_header(title: str, width: Optional[int] = None):
    """Print a styled header"""
    if not width:
        width = get_terminal_size().columns
    
    print(f"{Colors.BG_DARK_BLUE}{Colors.BOLD}")
    print("=" * width)
    print(f"{title.center(width)}")
    print("=" * width)
    print(f"{Colors.ENDC}")

def print_status(message: str, status: str = "INFO", timestamp: bool = True):
    """Print a status message with color coding"""
    colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN,
        "WARNING": Colors.WARNING,
        "ERROR": Colors.FAIL,
        "ALERT": Colors.FAIL + Colors.BOLD
    }
    color = colors.get(status.upper(), Colors.BLUE)
    
    time_str = f"[{datetime.now().strftime('%H:%M:%S')}] " if timestamp else ""
    print(f"{color}{time_str}[{status.upper()}] {message}{Colors.ENDC}")

def print_section(title: str):
    """Print a section header"""
    width = get_terminal_size().columns
    print(f"\n{Colors.CYAN}{Colors.BOLD}{title}")
    print(f"{'-' * min(len(title) + 2, width)}{Colors.ENDC}\n")

def create_menu(options: list, title: str = "Menu") -> int:
    """Create an interactive menu"""
    while True:
        print_section(title)
        for i, option in enumerate(options, 1):
            print(f"{Colors.CYAN}{i}.{Colors.ENDC} {option}")
        
        try:
            choice = int(input(f"\n{Colors.BOLD}Enter your choice (1-{len(options)}): {Colors.ENDC}"))
            if 1 <= choice <= len(options):
                return choice
        except ValueError:
            pass
        
        print_status("Invalid choice! Please try again.", "ERROR")

def progress_bar(current: int, total: int, prefix: str = '', suffix: str = '', length: int = 50):
    """Display a progress bar"""
    filled = int(length * current / total)
    bar = f"{Colors.BLUE}{'█' * filled}{Colors.WARNING}{'░' * (length - filled)}{Colors.ENDC}"
    percent = f"{Colors.BOLD}{100 * current / total:.1f}%{Colors.ENDC}"
    print(f'\r{prefix} |{bar}| {percent} {suffix}', end='\r')
    if current == total:
        print()

def init_ui():
    """Initialize the UI"""
    setup_console()
    clear_screen()
    
    # Set terminal title if supported
    if platform.system() != 'Windows':
        sys.stdout.write("\x1b]2;ACDC Security Suite\x07")
    
    # Print welcome screen
    width = get_terminal_size().columns
    print(f"{Colors.BG_DARK_BLUE}{Colors.BOLD}")
    print("=" * width)
    print("Advanced Cyber Defense Console (ACDC)".center(width))
    print("Security Analysis Suite".center(width))
    print("=" * width)
    print(f"{Colors.ENDC}")

# Web-specific utilities
def format_web_log(message: str, level: str = "INFO", module: str = "") -> str:
    """Format log message for web display"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    return {
        'timestamp': timestamp,
        'level': level,
        'message': message,
        'module': module
    }

def create_notification(message: str, type: str = "info") -> str:
    """Create HTML notification"""
    return f"""
    <div class="notification {type}">
        <i class="fas fa-{type}-circle me-2"></i>
        {message}
    </div>
    """

def format_web_log(message: str, level: str = "INFO") -> str:
    """Format log message for web display"""
    level_colors = {
        "INFO": WebColors.TEXT_PRIMARY,
        "SUCCESS": "#10b981",
        "WARNING": "#f59e0b",
        "ERROR": "#ef4444",
        "CRITICAL": "#dc2626"
    }
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = level_colors.get(level.upper(), WebColors.TEXT_PRIMARY)
    
    return f"""
    <div class="log-entry">
        <span class="log-timestamp">{timestamp}</span>
        <span class="log-level log-level-{level.upper()}">{level.upper()}</span>
        <span class="log-message" style="color: {color}">{message}</span>
    </div>
    """

def create_module_card(
    module_name: str,
    icon: str,
    description: str,
    status: str = "stopped",
    gradient: str = None
) -> str:
    """Generate HTML for a module card"""
    status_class = "running" if status == "running" else "stopped"
    gradient = gradient or WebColors.PRIMARY_GRADIENT
    
    return f"""
    <div class="module-card" id="{module_name}-card">
        <div class="module-icon" style="background: {gradient}">
            <i class="fas fa-{icon}"></i>
        </div>
        <h5 class="module-title">{module_name.title()}</h5>
        <p class="module-description">{description}</p>
        <div class="module-controls">
            <div>
                <span id="{module_name}-status" class="status-badge {status_class}">
                    <i class="fas fa-circle"></i>
                    {status.title()}
                </span>
                <div id="{module_name}-uptime" class="uptime"></div>
            </div>
            <div class="control-buttons">
                <button onclick="startModule('{module_name}')" class="btn-control btn-start">
                    <i class="fas fa-play me-1"></i>Start
                </button>
                <button onclick="stopModule('{module_name}')" class="btn-control btn-stop">
                    <i class="fas fa-stop me-1"></i>Stop
                </button>
            </div>
        </div>
    </div>
    """

def init_web_ui():
    """Initialize web UI"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ACDC Security Suite - Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --dark-bg: {WebColors.DARK_BG};
                --card-bg: {WebColors.CARD_BG};
                --card-border: {WebColors.CARD_BORDER};
                --text-primary: {WebColors.TEXT_PRIMARY};
                --text-secondary: {WebColors.TEXT_SECONDARY};
                --text-muted: {WebColors.TEXT_MUTED};
            }}
            
            /* Add the CSS provided in the HTML template */
            /* ... (copy all CSS from the HTML template) ... */
        </style>
    </head>
    <body>
        <div class="bg-animated"></div>
        <!-- Add the rest of the HTML structure -->
    </body>
    </html>
    """
