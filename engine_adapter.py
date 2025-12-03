"""
PortPhantom Engine Adapter
Thin wrapper around scanner.py for GUI integration
"""

import threading
import queue
import time
from typing import Callable, Dict, List, Optional, Any
import sys


class EngineAdapter:
    """
    Adapter layer between GUI and scanner.py
    Handles threading, Scapy detection, and provides GUI-friendly API
    """
    
    def __init__(self):
        self.scapy_available = self._detect_scapy()
        self.scanner_module = None
        self._load_scanner_module()
        
        # Threading control
        self.scan_thread = None
        self.stop_flag = threading.Event()
        self.result_queue = queue.Queue()
        self.is_scanning = False
        
        # Callbacks
        self.on_result_callback = None
        self.on_complete_callback = None
        self.on_error_callback = None
    
    def _detect_scapy(self) -> bool:
        """Detect if Scapy is available"""
        try:
            import scapy
            from scapy.all import IP, TCP, sr1
            return True
        except ImportError:
            return False
    
    def _load_scanner_module(self):
        """Import scanner.py module"""
        try:
            import scanner
            self.scanner_module = scanner
        except ImportError as e:
            raise ImportError(f"Could not import scanner.py: {e}")
    
    def parse_targets(self, raw_input: str, threads: int = 1) -> List[str]:
        """
        Parse target input (IP, CIDR, range) into list of IPs
        
        Args:
            raw_input: Target specification (e.g., "192.168.1.1", "192.168.1.0/24")
            threads: Number of threads (passed to scanner.py function)
        
        Returns:
            List of IP addresses as strings
        """
        if not raw_input or not raw_input.strip():
            return []
        
        try:
            hosts = self.scanner_module.getIPaddresses(raw_input.strip(), threads)
            return hosts if hosts else []
        except Exception as e:
            print(f"Error parsing targets: {e}")
            return []
    
    def get_port_list(self, port_mode: str, num_hosts: int = 1, 
                      start: int = 1, end: int = 65535, 
                      threads: int = 1, scan_type: str = "connect",
                      custom_ports: Optional[str] = None) -> List[int]:
        """
        Get list of ports based on mode
        
        Args:
            port_mode: "common", "all", "wellknown", "web", "database", etc.
            num_hosts: Number of hosts to scan
            start: Start port for range mode
            end: End port for range mode
            threads: Number of threads
            scan_type: Scan type (for compatibility)
            custom_ports: Comma-separated port list for "single" mode
        
        Returns:
            List of port numbers
        """
        try:
            ports = self.scanner_module.getPorts(
                portMode=port_mode,
                numberOfHosts=num_hosts,
                start=start,
                end=end,
                threads=threads,
                scanType=scan_type,
                inputPorts=custom_ports
            )
            return ports if ports else []
        except Exception as e:
            print(f"Error getting ports: {e}")
            return []
    
    def start_scan(self, config: Dict[str, Any], 
                   on_result: Callable[[Dict], None],
                   on_complete: Optional[Callable[[], None]] = None,
                   on_error: Optional[Callable[[str], None]] = None):
        """
        Start a scan in background thread
        
        Args:
            config: Scan configuration dict with keys:
                - targets: List of IP addresses
                - ports: List of port numbers
                - scan_type: "connect", "syn", "ack", "fin", "rst"
                - threads: Number of threads
                - service_detection: bool
                - os_detection: bool
                - timeout: float
            on_result: Callback for each result (called with result dict)
            on_complete: Callback when scan completes
            on_error: Callback for errors
        """
        if self.is_scanning:
            if on_error:
                on_error("A scan is already running")
            return
        
        self.on_result_callback = on_result
        self.on_complete_callback = on_complete
        self.on_error_callback = on_error
        
        self.stop_flag.clear()
        self.is_scanning = True
        
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(config,),
            daemon=True
        )
        self.scan_thread.start()
    
    def _scan_worker(self, config: Dict[str, Any]):
        """Worker thread that performs the actual scanning"""
        try:
            targets = config.get("targets", [])
            ports = config.get("ports", [])
            scan_type = config.get("scan_type", "connect")
            threads = config.get("threads", 10)
            service_detection = config.get("service_detection", False)
            timeout = config.get("timeout", 1.0)
            
            if not targets or not ports:
                if self.on_error_callback:
                    self.on_error_callback("No targets or ports specified")
                self.is_scanning = False
                return
            
            # Check if Scapy scan is requested but not available
            if scan_type != "connect" and not self.scapy_available:
                if self.on_error_callback:
                    self.on_error_callback(
                        f"{scan_type.upper()} scan requires Scapy (not installed). "
                        "Using Connect scan instead."
                    )
                scan_type = "connect"
            
            # Use multithreading for faster scanning
            total_scans = len(targets) * len(ports)
            scans_completed = 0
            completed_lock = threading.Lock()
            
            def scan_target_worker(target):
                """Worker function for each target"""
                nonlocal scans_completed
                
                for port in ports:
                    if self.stop_flag.is_set():
                        break
                    
                    result = self._scan_single_port(
                        target, port, scan_type, service_detection, timeout
                    )
                    
                    with completed_lock:
                        scans_completed += 1
                        progress = (scans_completed / total_scans) * 100
                    
                    if self.on_result_callback:
                        try:
                            self.on_result_callback({
                                "type": "progress",
                                "progress": progress,
                                "completed": scans_completed,
                                "total": total_scans
                            })
                        except Exception as e:
                            print(f"Error reporting progress: {e}")
                    
                    if result:
                        if self.on_result_callback:
                            try:
                                self.on_result_callback(result)
                            except Exception as e:
                                print(f"Error in result callback: {e}")
            
            # Create and start worker threads
            scan_threads = []
            max_threads = min(threads, len(targets))
            
            targets_per_thread = len(targets) // max_threads
            remainder = len(targets) % max_threads
            
            start_idx = 0
            for i in range(max_threads):
                end_idx = start_idx + targets_per_thread + (1 if i < remainder else 0)
                thread_targets = targets[start_idx:end_idx]
                
                for target in thread_targets:
                    if self.stop_flag.is_set():
                        break
                    
                    thread = threading.Thread(
                        target=scan_target_worker,
                        args=(target,),
                        daemon=True
                    )
                    scan_threads.append(thread)
                    thread.start()
                
                start_idx = end_idx
            
            for thread in scan_threads:
                thread.join()
            
            if self.on_complete_callback and not self.stop_flag.is_set():
                try:
                    self.on_complete_callback()
                except Exception as e:
                    print(f"Error in complete callback: {e}")
        
        except Exception as e:
            print(f"Scan error: {e}")
            if self.on_error_callback:
                try:
                    self.on_error_callback(str(e))
                except Exception as callback_error:
                    print(f"Error in error callback: {callback_error}")
        
        finally:
            self.is_scanning = False
    
    def _scan_single_port(self, target: str, port: int, scan_type: str,
                          service_detection: bool, timeout: float) -> Optional[Dict]:
        """
        Scan a single port on a target
        
        Returns:
            Dict with scan result or None if port is closed/filtered
        """
        try:
            if scan_type == "connect":
                result = self.scanner_module.scan_port_connect(
                    target, port, service_detection
                )
                
                # FIX: scanner.py returns 'OPEN' (uppercase), so check uppercase
                if result and result.get("state", "").upper() == "OPEN":
                    return {
                        "type": "result",
                        "host": target,
                        "port": port,
                        "state": result.get("state", "open"),
                        "service": result.get("service", "unknown"),
                        "banner": result.get("banner", ""),
                        "scan_type": "connect"
                    }
            
            elif self.scapy_available:
                flag_map = {
                    "syn": "S",
                    "ack": "A", 
                    "fin": "F",
                    "rst": "R"
                }
                flag = flag_map.get(scan_type, "S")
                
                result = self.scanner_module.scanPort(
                    host=target,
                    scanningPort=port,
                    flag=flag,
                    scanType=scan_type
                )
                
                # FIX: Case-insensitive check for state
                state = result.get("state", "").upper() if result else ""
                if state in ["OPEN", "OPEN|FILTERED"]:
                    service = "unknown"
                    banner = ""
                    
                    if service_detection:
                        try:
                            service_result = self.scanner_module.scan_port_connect(
                                target, port, True
                            )
                            if service_result:
                                service = service_result.get("service", "unknown")
                                banner = service_result.get("banner", "")
                        except:
                            common_ports = self.get_common_ports_dict()
                            service = common_ports.get(port, "unknown")
                    else:
                        common_ports = self.get_common_ports_dict()
                        service = common_ports.get(port, "unknown")
                    
                    return {
                        "type": "result",
                        "host": target,
                        "port": port,
                        "state": result.get("state", "open"),
                        "service": service,
                        "banner": banner,
                        "scan_type": scan_type
                    }
            
            return None
            
        except Exception as e:
            return None
    
    def stop_scan(self):
        """Stop the currently running scan"""
        if self.is_scanning:
            self.stop_flag.set()
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=2.0)
            self.is_scanning = False
    
    def get_common_ports_dict(self) -> Dict[int, str]:
        """Get the common ports dictionary from scanner.py"""
        try:
            return self.scanner_module.common_ports_dict
        except AttributeError:
            return {}
    
    def get_available_scan_types(self) -> List[str]:
        """Get list of available scan types based on Scapy availability"""
        if self.scapy_available:
            return ["connect", "syn", "ack", "fin", "rst"]
        else:
            return ["connect"]
