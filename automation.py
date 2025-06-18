import os
import subprocess
import re
import csv
import json
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('automation.log'),
        logging.StreamHandler()
    ]
)

# === MODULE STATUS TRACKING ===

class ModuleStatus:
    def __init__(self):
        self.history_file = "module_history.json"
        self.load_history()

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.history = json.load(f)
            else:
                self.history = []
        except Exception as e:
            logging.error(f"Failed to load history: {e}")
            self.history = []

    def save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save history: {e}")

    def add_run(self, module: str, success: bool, error: Optional[str] = None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "success": success,
            "error": error
        }
        self.history.append(entry)
        self.save_history()

module_status = ModuleStatus()

# Add after ModuleStatus class
def get_current_status():
    """Get current status of all modules for API"""
    return {
        'history': module_status.history,
        'current_runs': {
            'honeypot': False,
            'network': False,
            'cryptanalysis': False,
            'endpoint': False
        }
    }

# === MODULE RUNNERS ===

def run_module(name: str, script: str) -> bool:
    try:
        logging.info(f"Running {name} Module...")
        print(f"\n[INFO] Running {name} Module...")
        subprocess.run(["python", script], check=True)
        module_status.add_run(name, True)
        return True
    except subprocess.CalledProcessError as e:
        error_msg = f"{name} module failed: {e}"
        logging.error(error_msg)
        print(f"[ERROR] {error_msg}")
        module_status.add_run(name, False, str(e))
        return False

def run_honeypot():
    return run_module("Honeypot", "honeypot.py")

def run_network():
    return run_module("Network", "network.py")

def run_cryptanalysis():
    return run_module("Cryptanalysis", "cryptanalysis.py")

def run_endpoint():
    return run_module("Endpoint", "endpoint.py")

def run_all_modules():
    print("\n[INFO] Running All Modules...")
    logging.info("Running all modules")
    
    results = {
        "Honeypot": run_honeypot(),
        "Network": run_network(),
        "Cryptanalysis": run_cryptanalysis(),
        "Endpoint": run_endpoint()
    }
    
    successes = sum(results.values())
    print(f"\n=== Module Run Summary ===")
    for module, success in results.items():
        status = "\033[92m✓\033[0m" if success else "\033[91m✗\033[0m"
        print(f"{status} {module}")
    print(f"\nSuccessful: {successes}/{len(results)}")

# === LOG REPORT VIEWER ===

def view_log_report():
    print("\n[INFO] Viewing Honeypot Log Report...")
    log_file = "honeypot.log"

    if not os.path.exists(log_file):
        print("[WARNING] Log file not found.")
        return

    try:
        with open(log_file, 'r') as file:
            lines = file.readlines()

        if not lines:
            print("[INFO] Log file is empty.")
            return

        summary = defaultdict(int)
        attackers = defaultdict(int)

        print("\n--- Honeypot Log Entries ---")
        for line in lines:
            line = line.strip()

            if "HTTP" in line:
                summary["HTTP"] += 1
            elif "Telnet" in line:
                summary["Telnet"] += 1

            if "WARNING" in line:
                summary["Attacks"] += 1
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    attackers[ip_match.group(1)] += 1

            # Print color-coded lines
            if "WARNING" in line:
                print(f"\033[91m{line}\033[0m")  # Red
            elif "INFO" in line:
                print(f"\033[94m{line}\033[0m")  # Blue
            else:
                print(line)

        # Summary
        print("\n--- Summary ---")
        for key, count in summary.items():
            print(f"{key}: {count}")

        if attackers:
            print("\nTop Attacker IPs:")
            for ip, count in sorted(attackers.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip} - {count} attack(s)")

        print("\n[INFO] End of log report.\n")

    except Exception as e:
        print(f"[ERROR] Failed to read logs: {e}")

# === CSV EXPORTER ===

def export_logs_to_csv():
    log_file = "honeypot.log"
    csv_file = "log_summary.csv"

    if not os.path.exists(log_file):
        print("[WARNING] Log file not found.")
        return

    try:
        with open(log_file, 'r') as file:
            lines = file.readlines()

        if not lines:
            print("[INFO] Log file is empty.")
            return

        data = []
        for line in lines:
            line = line.strip()
            timestamp_match = re.search(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})", line)
            module_match = re.search(r"\[(.*?)\]", line)
            level_match = re.search(r"- (INFO|WARNING|ERROR) -", line)
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            event = line.split(" - ")[-1]

            data.append({
                "Timestamp": timestamp_match.group(1) if timestamp_match else "",
                "Module": module_match.group(1) if module_match else "",
                "Level": level_match.group(1) if level_match else "",
                "IP": ip_match.group(1) if ip_match else "",
                "Event": event
            })

        with open(csv_file, 'w', newline='') as csvfile:
            fieldnames = ["Timestamp", "Module", "Level", "IP", "Event"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        print(f"\n[INFO] Log successfully exported to {csv_file}\n")

    except Exception as e:
        print(f"[ERROR] Could not export log: {e}")

def show_module_status():
    """Display module run history and status"""
    if not module_status.history:
        print("\n[INFO] No module run history available.")
        return

    print("\n=== Module Run History ===")
    
    module_stats = defaultdict(lambda: {"total": 0, "success": 0})
    
    # Process history in reverse (most recent first)
    for entry in reversed(module_status.history[-10:]):  # Show last 10 entries
        timestamp = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        status = "\033[92m✓\033[0m" if entry["success"] else "\033[91m✗\033[0m"
        print(f"{timestamp} | {status} {entry['module']}")
        if not entry["success"] and entry.get("error"):
            print(f"    └─ Error: {entry['error']}")

        # Update stats
        module_stats[entry["module"]]["total"] += 1
        if entry["success"]:
            module_stats[entry["module"]]["success"] += 1

    # Show statistics
    print("\n=== Module Statistics ===")
    for module, stats in module_stats.items():
        success_rate = (stats["success"] / stats["total"]) * 100
        print(f"{module}: {stats['success']}/{stats['total']} ({success_rate:.1f}% success)")

# Add before main()
def run_module_api(module_name: str) -> Dict:
    """Run module from API call"""
    try:
        if module_name == 'honeypot':
            success = run_honeypot()
        elif module_name == 'network':
            success = run_network()
        elif module_name == 'cryptanalysis':
            success = run_cryptanalysis()
        elif module_name == 'endpoint':
            success = run_endpoint()
        elif module_name == 'all':
            success = all(run_all_modules().values())
        else:
            return {'status': 'error', 'message': 'Invalid module'}
        
        return {
            'status': 'success' if success else 'error',
            'message': f'Module {module_name} completed successfully' if success else f'Module {module_name} failed'
        }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

# === MENU INTERFACE ===

def main():
    while True:
        print("\n" + "=" * 50)
        print("Security Module Automation Interface")
        print("=" * 50)
        print("1. Run Honeypot Module")
        print("2. Run Network Monitor Module")
        print("3. Run Cryptanalysis Module")
        print("4. Run Endpoint Security Module")
        print("5. Run All Modules")
        print("6. View Honeypot Logs and Summary")
        print("7. Export Honeypot Logs to CSV")
        print("8. Show Module Status")
        print("9. Exit")
        print("-" * 50)

        choice = input("Enter your choice (1-9): ")
        try:
            if choice == '1':
                run_honeypot()
            elif choice == '2':
                run_network()
            elif choice == '3':
                run_cryptanalysis()
            elif choice == '4':
                run_endpoint()
            elif choice == '5':
                run_all_modules()
            elif choice == '6':
                view_log_report()
            elif choice == '7':
                export_logs_to_csv()
            elif choice == '8':
                show_module_status()
            elif choice == '9':
                print("\nExiting...")
                break
            else:
                print("\n[WARNING] Invalid choice. Please enter a number between 1 and 9.")
        except KeyboardInterrupt:
            print("\n[!] Program interrupted by user. Exiting...")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            print(f"\n[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
# This code is part of a security monitoring system that allows users to run various security modules,