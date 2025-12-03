"""
PortPhantom Enhancement Features
Queue, Recovery, Notifications, Export Manager, Quick Actions
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import threading


# ===== SCAN QUEUE MANAGER =====

class QueueManager:
    """Manages scan job queue"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.queue_file = self.config_dir / "queue.json"
        self.jobs = []
        self.current_job_index = -1
        self._load_queue()
    
    def _load_queue(self):
        """Load queue from file"""
        if self.queue_file.exists():
            try:
                with open(self.queue_file, 'r') as f:
                    data = json.load(f)
                    self.jobs = data.get("jobs", [])
                    self.current_job_index = data.get("current_job_index", -1)
            except Exception as e:
                print(f"Could not load queue: {e}")
    
    def _save_queue(self):
        """Save queue to file"""
        try:
            self.config_dir.mkdir(exist_ok=True)
            with open(self.queue_file, 'w') as f:
                json.dump({
                    "jobs": self.jobs,
                    "current_job_index": self.current_job_index
                }, f, indent=2)
        except Exception as e:
            print(f"Could not save queue: {e}")
    
    def add_job(self, job_config: Dict[str, Any]) -> int:
        """Add a job to the queue"""
        job = {
            "id": len(self.jobs),
            "name": job_config.get("name", f"Scan {len(self.jobs) + 1}"),
            "target": job_config.get("target", ""),
            "port_mode": job_config.get("port_mode", "common"),
            "scan_type": job_config.get("scan_type", "connect"),
            "threads": job_config.get("threads", 10),
            "service_detection": job_config.get("service_detection", False),
            "status": "pending",
            "created": datetime.now().isoformat(),
            "completed": None,
            "results_count": 0
        }
        self.jobs.append(job)
        self._save_queue()
        return job["id"]
    
    def get_job(self, job_id: int) -> Optional[Dict]:
        """Get a job by ID"""
        for job in self.jobs:
            if job["id"] == job_id:
                return job
        return None
    
    def update_job_status(self, job_id: int, status: str, results_count: int = 0):
        """Update job status"""
        job = self.get_job(job_id)
        if job:
            job["status"] = status
            job["results_count"] = results_count
            if status in ["complete", "failed"]:
                job["completed"] = datetime.now().isoformat()
            self._save_queue()
    
    def get_pending_jobs(self) -> List[Dict]:
        """Get all pending jobs"""
        return [job for job in self.jobs if job["status"] == "pending"]
    
    def get_all_jobs(self) -> List[Dict]:
        """Get all jobs"""
        return self.jobs
    
    def remove_job(self, job_id: int) -> bool:
        """Remove a job from queue"""
        self.jobs = [job for job in self.jobs if job["id"] != job_id]
        self._save_queue()
        return True
    
    def clear_completed(self):
        """Clear all completed/failed jobs"""
        self.jobs = [job for job in self.jobs if job["status"] not in ["complete", "failed"]]
        self._save_queue()
    
    def clear_all(self):
        """Clear entire queue"""
        self.jobs = []
        self.current_job_index = -1
        self._save_queue()


# ===== RECOVERY MANAGER =====

class RecoveryManager:
    """Auto-save and crash recovery"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.recovery_file = self.config_dir / "recovery.json"
        self.auto_save_interval = 30  # seconds
        self.auto_save_timer = None
        self.is_active = False
    
    def start_auto_save(self, save_callback: Callable[[], Dict]):
        """Start auto-save timer"""
        self.save_callback = save_callback
        self.is_active = True
        self._schedule_auto_save()
    
    def stop_auto_save(self):
        """Stop auto-save timer"""
        self.is_active = False
        if self.auto_save_timer:
            self.auto_save_timer.cancel()
    
    def _schedule_auto_save(self):
        """Schedule next auto-save"""
        if self.is_active:
            self.auto_save_timer = threading.Timer(
                self.auto_save_interval,
                self._perform_auto_save
            )
            self.auto_save_timer.daemon = True
            self.auto_save_timer.start()
    
    def _perform_auto_save(self):
        """Perform auto-save"""
        try:
            data = self.save_callback()
            self.save_recovery_data(data)
        except Exception as e:
            print(f"Auto-save error: {e}")
        
        self._schedule_auto_save()
    
    def save_recovery_data(self, data: Dict):
        """Save recovery data"""
        try:
            self.config_dir.mkdir(exist_ok=True)
            recovery_data = {
                "timestamp": datetime.now().isoformat(),
                "data": data
            }
            with open(self.recovery_file, 'w') as f:
                json.dump(recovery_data, f, indent=2)
        except Exception as e:
            print(f"Could not save recovery data: {e}")
    
    def load_recovery_data(self) -> Optional[Dict]:
        """Load recovery data"""
        if not self.recovery_file.exists():
            return None
        
        try:
            with open(self.recovery_file, 'r') as f:
                recovery_data = json.load(f)
                return recovery_data.get("data")
        except Exception as e:
            print(f"Could not load recovery data: {e}")
            return None
    
    def has_recovery_data(self) -> bool:
        """Check if recovery data exists"""
        return self.recovery_file.exists()
    
    def clear_recovery_data(self):
        """Clear recovery data"""
        try:
            if self.recovery_file.exists():
                self.recovery_file.unlink()
        except Exception as e:
            print(f"Could not clear recovery data: {e}")
    
    def get_recovery_info(self) -> Optional[Dict]:
        """Get recovery data info"""
        if not self.recovery_file.exists():
            return None
        
        try:
            with open(self.recovery_file, 'r') as f:
                recovery_data = json.load(f)
                return {
                    "timestamp": recovery_data.get("timestamp"),
                    "has_results": len(recovery_data.get("data", {}).get("results", [])) > 0
                }
        except:
            return None


# ===== NOTIFICATION MANAGER =====

class NotificationManager:
    """Desktop notifications"""
    
    def __init__(self):
        self.enabled = True
        self.sound_enabled = False
        self._check_platform()
    
    def _check_platform(self):
        """Check platform for notification support"""
        import platform
        self.platform = platform.system()
    
    def notify(self, title: str, message: str, sound: bool = False):
        """Send desktop notification"""
        if not self.enabled:
            return
        
        try:
            if self.platform == "Windows":
                self._notify_windows(title, message)
            elif self.platform == "Darwin":
                self._notify_macos(title, message)
            elif self.platform == "Linux":
                self._notify_linux(title, message)
        except Exception as e:
            print(f"Notification error: {e}")
        
        if sound and self.sound_enabled:
            self._play_sound()
    
    def _notify_windows(self, title: str, message: str):
        """Windows notification"""
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(
                title,
                message,
                icon_path=None,
                duration=5,
                threaded=True
            )
        except ImportError:
            print(f"Notification: {title} - {message}")
    
    def _notify_macos(self, title: str, message: str):
        """macOS notification"""
        os.system(f"""
            osascript -e 'display notification "{message}" with title "{title}"'
        """)
    
    def _notify_linux(self, title: str, message: str):
        """Linux notification"""
        os.system(f'notify-send "{title}" "{message}"')
    
    def _play_sound(self):
        """Play notification sound"""
        try:
            if self.platform == "Windows":
                import winsound
                winsound.MessageBeep()
            else:
                print('\a')
        except:
            pass
    
    def set_enabled(self, enabled: bool):
        """Enable/disable notifications"""
        self.enabled = enabled
    
    def set_sound_enabled(self, enabled: bool):
        """Enable/disable notification sound"""
        self.sound_enabled = enabled


# ===== EXPORT MANAGER =====

class ExportManager:
    """Enhanced export functionality"""
    
    def __init__(self, export_dir: str = "exports"):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(exist_ok=True)
    
    def export_txt(self, results: List[Dict], filename: str, 
                   include_metadata: bool = True) -> bool:
        """Export to text file"""
        try:
            filepath = self.export_dir / filename
            with open(filepath, 'w') as f:
                if include_metadata:
                    f.write("=" * 80 + "\n")
                    f.write("PortPhantom Scan Results\n")
                    f.write("=" * 80 + "\n")
                    f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Results: {len(results)}\n")
                    f.write("=" * 80 + "\n\n")
                
                for result in results:
                    f.write(f"Host: {result.get('host', 'unknown')}\n")
                    f.write(f"Port: {result.get('port', 'unknown')}\n")
                    f.write(f"State: {result.get('state', 'unknown')}\n")
                    f.write(f"Service: {result.get('service', 'unknown')}\n")
                    if result.get('banner'):
                        f.write(f"Banner: {result.get('banner', '')}\n")
                    f.write("-" * 80 + "\n")
            
            return True
        except Exception as e:
            print(f"Export TXT error: {e}")
            return False
    
    def export_csv(self, results: List[Dict], filename: str) -> bool:
        """Export to CSV file"""
        try:
            import csv
            filepath = self.export_dir / filename
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Host', 'Port', 'State', 'Service', 'Banner', 'Scan Type'])
                
                for result in results:
                    writer.writerow([
                        result.get('host', ''),
                        result.get('port', ''),
                        result.get('state', ''),
                        result.get('service', ''),
                        result.get('banner', ''),
                        result.get('scan_type', '')
                    ])
            
            return True
        except Exception as e:
            print(f"Export CSV error: {e}")
            return False
    
    def export_json(self, results: List[Dict], filename: str,
                    include_metadata: bool = True) -> bool:
        """Export to JSON file"""
        try:
            filepath = self.export_dir / filename
            export_data = {
                "results": results
            }
            
            if include_metadata:
                export_data["metadata"] = {
                    "export_date": datetime.now().isoformat(),
                    "total_results": len(results),
                    "exporter": "PortPhantom v1.0"
                }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Export JSON error: {e}")
            return False
    
    def export_html(self, results: List[Dict], filename: str) -> bool:
        """Export to HTML file"""
        try:
            filepath = self.export_dir / filename
            
            html = """<!DOCTYPE html>
<html>
<head>
    <title>PortPhantom Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
        h1 { color: #4a9eff; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #2a2a2a; padding: 10px; text-align: left; border: 1px solid #444; }
        td { padding: 8px; border: 1px solid #444; }
        .open { color: #00ff00; }
        .closed { color: #ff6666; }
        .filtered { color: #ffaa00; }
        tr:hover { background: #2a2a2a; }
    </style>
</head>
<body>
    <h1>PortPhantom Scan Results</h1>
    <p>Export Date: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    <p>Total Results: """ + str(len(results)) + """</p>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Banner</th>
        </tr>
"""
            
            for result in results:
                state = result.get('state', 'unknown')
                state_class = state.lower()
                html += f"""        <tr>
            <td>{result.get('host', '')}</td>
            <td>{result.get('port', '')}</td>
            <td class="{state_class}">{state}</td>
            <td>{result.get('service', '')}</td>
            <td>{result.get('banner', '')[:100]}</td>
        </tr>
"""
            
            html += """    </table>
</body>
</html>"""
            
            with open(filepath, 'w') as f:
                f.write(html)
            
            return True
        except Exception as e:
            print(f"Export HTML error: {e}")
            return False
    
    def get_export_path(self, filename: str) -> Path:
        """Get full export file path"""
        return self.export_dir / filename


# ===== QUICK ACTIONS =====

class QuickActions:
    """Context menu and keyboard shortcuts"""
    
    def __init__(self):
        self.actions = {}
    
    def register_action(self, name: str, callback: Callable, shortcut: Optional[str] = None):
        """Register a quick action"""
        self.actions[name] = {
            "callback": callback,
            "shortcut": shortcut
        }
    
    def get_action(self, name: str) -> Optional[Dict]:
        """Get action by name"""
        return self.actions.get(name)
    
    def execute_action(self, name: str, *args, **kwargs):
        """Execute an action"""
        action = self.actions.get(name)
        if action:
            try:
                action["callback"](*args, **kwargs)
            except Exception as e:
                print(f"Action error: {e}")
