"""
PortPhantom GUI - Network Port Scanner
Complete implementation with all enhancement features
"""

import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
from typing import Optional, Dict, List, Any
from datetime import datetime
import sys
import os
import webbrowser

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False
    print("Warning: tkinterdnd2 not available - drag & drop disabled")

# Import our custom modules
from config_manager import ConfigManager, ProfileManager
from engine_adapter import EngineAdapter
from features import (
    QueueManager, RecoveryManager, NotificationManager,
    ExportManager, QuickActions
)


class PortPhantomGUI(ctk.CTk if not DND_AVAILABLE else ctk.CTk):
    """Main application window for PortPhantom"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize drag & drop if available
        if DND_AVAILABLE:
            try:
                TkinterDnD.DnDWrapper.__init__(self)
                self.TkdndVersion = TkinterDnD._require(self)
            except:
                pass
        
        # Initialize managers
        self.config_manager = ConfigManager()
        self.profile_manager = ProfileManager()
        self.engine = EngineAdapter()
        self.queue_manager = QueueManager()
        self.recovery_manager = RecoveryManager()
        self.notification_manager = NotificationManager()
        self.export_manager = ExportManager()
        self.quick_actions = QuickActions()
        
        # Application state
        self.is_scanning = False
        self.scan_start_time = None
        self.scan_results = []
        self.result_queue = queue.Queue()
        self.current_queue_job_id = None
        
        # Setup window
        self._setup_window()
        
        # Build UI
        self._build_menu_bar()
        self._build_main_layout()
        self._build_scan_section()
        self._build_queue_section()
        self._build_results_section()
        self._build_details_panel()
        self._build_status_bar()
        
        # Setup features
        self._setup_quick_actions()
        self._setup_context_menu()
        
        # Load settings
        self._load_settings()
        
        # Setup drag and drop
        if DND_AVAILABLE:
            self._setup_drag_drop()
        
        # Check for recovery data
        self._check_recovery()
        
        # Start result queue processor
        self._process_result_queue()
        
        # Start auto-save
        self.recovery_manager.start_auto_save(self._get_recovery_data)
        
        # Bind close event
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _setup_window(self):
        """Configure main window properties"""
        self.title("PortPhantom - Network Port Scanner")
        
        # Set theme
        ctk.set_appearance_mode(self.config_manager.get("theme", "dark"))
        ctk.set_default_color_theme("blue")
        
        # Set window size from config
        width = self.config_manager.get("window.width", 1400)
        height = self.config_manager.get("window.height", 900)
        x = self.config_manager.get("window.x", 50)
        y = self.config_manager.get("window.y", 50)
        
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(1000, 700)
    
    def _build_menu_bar(self):
        """Build the menu bar"""
        from tkinter import Menu
        
        menubar = Menu(self)
        self.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Targets from File...", command=self._load_targets_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Export Results...", command=self._export_results_dialog, accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label="Clear Recent Targets", command=self._clear_recent_targets)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing, accelerator="Alt+F4")
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Manage Profiles...", command=self._manage_profiles, accelerator="Ctrl+P")
        tools_menu.add_command(label="Manage Queue...", command=self._show_queue_manager, accelerator="Ctrl+Q")
        tools_menu.add_command(label="Settings...", command=self._show_settings, accelerator="Ctrl+,")
        tools_menu.add_separator()
        tools_menu.add_command(label="Clear Results", command=self._clear_results, accelerator="Ctrl+L")
        tools_menu.add_command(label="Clear Queue", command=self._clear_queue)
        
        # View menu
        view_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Show Only Open Ports", command=lambda: self._quick_filter("open"), accelerator="Ctrl+1")
        view_menu.add_command(label="Show All Results", command=lambda: self._quick_filter("all"), accelerator="Ctrl+0")
        view_menu.add_separator()
        view_menu.add_command(label="Toggle Details Panel", command=self._toggle_details_panel, accelerator="F9")
        view_menu.add_command(label="Toggle Queue Panel", command=self._toggle_queue_panel, accelerator="F10")
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About PortPhantom", command=self._show_about)
        help_menu.add_command(label="Scapy Status", command=self._show_scapy_status)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        
        # Bind keyboard shortcuts
        self.bind_all("<Control-o>", lambda e: self._load_targets_file())
        self.bind_all("<Control-e>", lambda e: self._export_results_dialog())
        self.bind_all("<Control-p>", lambda e: self._manage_profiles())
        self.bind_all("<Control-q>", lambda e: self._show_queue_manager())
        self.bind_all("<Control-l>", lambda e: self._clear_results())
        self.bind_all("<Control-Key-1>", lambda e: self._quick_filter("open"))
        self.bind_all("<Control-Key-0>", lambda e: self._quick_filter("all"))
        self.bind_all("<F5>", lambda e: self._start_scan() if not self.is_scanning else None)
        self.bind_all("<Escape>", lambda e: self._stop_scan() if self.is_scanning else None)
        self.bind_all("<F9>", lambda e: self._toggle_details_panel())
        self.bind_all("<F10>", lambda e: self._toggle_queue_panel())
    
    def _build_main_layout(self):
        """Setup main layout grid"""
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)  # Details panel column
        self.grid_rowconfigure(2, weight=1)  # Results section gets weight
    
    def _build_scan_section(self):
        """Build the scan configuration section"""
        scan_frame = ctk.CTkFrame(self)
        scan_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="ew")
        scan_frame.grid_columnconfigure(1, weight=1)
        
        # Profile Selection
        profile_label = ctk.CTkLabel(scan_frame, text="Profile:", width=100, anchor="w")
        profile_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        profile_combo_frame = ctk.CTkFrame(scan_frame)
        profile_combo_frame.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        profile_combo_frame.grid_columnconfigure(0, weight=1)
        
        self.profile_var = ctk.StringVar(value="Custom")
        self.profile_combo = ctk.CTkComboBox(
            profile_combo_frame,
            variable=self.profile_var,
            values=["Custom"] + self.profile_manager.list_profiles(),
            command=self._on_profile_selected,
            width=300
        )
        self.profile_combo.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        ctk.CTkButton(
            profile_combo_frame,
            text="💾 Save",
            command=self._save_current_as_profile,
            width=80
        ).grid(row=0, column=1, padx=5, pady=5)
        
        ctk.CTkButton(
            profile_combo_frame,
            text="⚙ Manage",
            command=self._manage_profiles,
            width=80
        ).grid(row=0, column=2, padx=5, pady=5)
        
        # Target Input
        target_label = ctk.CTkLabel(scan_frame, text="Target(s):", width=100, anchor="w")
        target_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        target_frame = ctk.CTkFrame(scan_frame)
        target_frame.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        target_frame.grid_columnconfigure(0, weight=1)
        
        target_input_frame = ctk.CTkFrame(target_frame)
        target_input_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        target_input_frame.grid_columnconfigure(0, weight=1)
        
        self.target_entry = ctk.CTkEntry(
            target_input_frame,
            placeholder_text="Enter target or drag & drop file here (IP, CIDR, range)"
        )
        self.target_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        self.recent_btn = ctk.CTkButton(
            target_input_frame,
            text="▼",
            command=self._show_recent_targets,
            width=30
        )
        self.recent_btn.grid(row=0, column=1, padx=5, pady=5)
        
        ctk.CTkButton(
            target_frame,
            text="📁 Load",
            command=self._load_targets_file,
            width=80
        ).grid(row=0, column=1, padx=5, pady=5)
        
        # Drop hint
        self.drop_hint_label = ctk.CTkLabel(
            target_frame,
            text="💡 Drag & drop .txt file with targets here" if DND_AVAILABLE else "⚠ Install tkinterdnd2 for drag & drop",
            text_color="gray" if DND_AVAILABLE else "orange",
            font=("Arial", 10)
        )
        self.drop_hint_label.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="w")
        
        # Port Configuration
        port_label = ctk.CTkLabel(scan_frame, text="Ports:", width=100, anchor="w")
        port_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        port_frame = ctk.CTkFrame(scan_frame)
        port_frame.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        
        self.port_mode_var = ctk.StringVar(value="common")
        port_modes = ["common", "wellknown", "all", "web", "database", "mail", 
                     "remoteAccess", "fileShare", "range", "single"]
        
        self.port_mode_combo = ctk.CTkComboBox(
            port_frame,
            variable=self.port_mode_var,
            values=port_modes,
            command=self._on_port_mode_changed,
            width=150
        )
        self.port_mode_combo.grid(row=0, column=0, padx=5, pady=5)
        
        # Port range/custom frames
        self.port_range_frame = ctk.CTkFrame(port_frame)
        ctk.CTkLabel(self.port_range_frame, text="Start:").grid(row=0, column=0, padx=5)
        self.port_start_entry = ctk.CTkEntry(self.port_range_frame, width=80)
        self.port_start_entry.insert(0, "1")
        self.port_start_entry.grid(row=0, column=1, padx=5)
        ctk.CTkLabel(self.port_range_frame, text="End:").grid(row=0, column=2, padx=5)
        self.port_end_entry = ctk.CTkEntry(self.port_range_frame, width=80)
        self.port_end_entry.insert(0, "1024")
        self.port_end_entry.grid(row=0, column=3, padx=5)
        
        self.port_custom_frame = ctk.CTkFrame(port_frame)
        ctk.CTkLabel(self.port_custom_frame, text="Ports:").grid(row=0, column=0, padx=5)
        self.port_custom_entry = ctk.CTkEntry(self.port_custom_frame, width=300,
                                              placeholder_text="80,443,8080")
        self.port_custom_entry.grid(row=0, column=1, padx=5)
        
        # Scan Type and Threads
        scan_type_label = ctk.CTkLabel(scan_frame, text="Scan Type:", width=100, anchor="w")
        scan_type_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        
        scan_config_frame = ctk.CTkFrame(scan_frame)
        scan_config_frame.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        
        self.scan_type_var = ctk.StringVar(value="connect")
        scan_types = self.engine.get_available_scan_types()
        
        self.scan_type_combo = ctk.CTkComboBox(
            scan_config_frame,
            variable=self.scan_type_var,
            values=scan_types,
            width=150
        )
        self.scan_type_combo.grid(row=0, column=0, padx=5, pady=5)
        
        if not self.engine.scapy_available:
            ctk.CTkLabel(
                scan_config_frame,
                text="⚠ Scapy not installed - only Connect scan available",
                text_color="orange"
            ).grid(row=0, column=1, padx=10, pady=5)
        
        ctk.CTkLabel(scan_config_frame, text="Threads:").grid(row=0, column=2, padx=(20, 5), pady=5)
        
        self.threads_var = ctk.IntVar(value=10)
        self.threads_slider = ctk.CTkSlider(
            scan_config_frame,
            from_=1,
            to=100,
            variable=self.threads_var,
            width=150
        )
        self.threads_slider.grid(row=0, column=3, padx=5, pady=5)
        
        self.threads_label = ctk.CTkLabel(scan_config_frame, text="10", width=30)
        self.threads_label.grid(row=0, column=4, padx=5, pady=5)
        self.threads_var.trace_add("write", self._update_thread_label)
        
        # Options
        options_label = ctk.CTkLabel(scan_frame, text="Options:", width=100, anchor="w")
        options_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        
        options_frame = ctk.CTkFrame(scan_frame)
        options_frame.grid(row=4, column=1, padx=10, pady=5, sticky="ew")
        
        self.service_detection_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            options_frame,
            text="Service Detection",
            variable=self.service_detection_var
        ).grid(row=0, column=0, padx=10, pady=5)
        
        self.os_detection_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            options_frame,
            text="OS Detection",
            variable=self.os_detection_var
        ).grid(row=0, column=1, padx=10, pady=5)
        
        self.vuln_scan_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            options_frame,
            text="Vulnerability Scan",
            variable=self.vuln_scan_var
        ).grid(row=0, column=2, padx=10, pady=5)
        
        # Control Buttons
        button_frame = ctk.CTkFrame(scan_frame)
        button_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=10)
        
        self.start_button = ctk.CTkButton(
            button_frame,
            text="▶ Start Scan (F5)",
            command=self._start_scan,
            width=150,
            height=40,
            fg_color="green",
            hover_color="darkgreen"
        )
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ctk.CTkButton(
            button_frame,
            text="⬛ Stop (Esc)",
            command=self._stop_scan,
            width=120,
            height=40,
            fg_color="red",
            hover_color="darkred",
            state="disabled"
        )
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ctk.CTkButton(
            button_frame,
            text="➕ Add to Queue",
            command=self._add_to_queue,
            width=130,
            height=40
        ).grid(row=0, column=2, padx=5)
    
    def _build_queue_section(self):
        """Build the scan queue section"""
        self.queue_frame = ctk.CTkFrame(self)
        self.queue_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        self.queue_frame.grid_columnconfigure(0, weight=1)
        
        # Title bar
        title_frame = ctk.CTkFrame(self.queue_frame)
        title_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        title_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(title_frame, text="Scan Queue", font=("Arial", 14, "bold")).grid(row=0, column=0, padx=10, pady=5)
        
        ctk.CTkButton(
            title_frame,
            text="▶ Execute Queue",
            command=self._execute_queue,
            width=120,
            fg_color="green"
        ).grid(row=0, column=1, padx=5, pady=5, sticky="e")
        
        ctk.CTkButton(
            title_frame,
            text="🗑 Clear Completed",
            command=lambda: self._clear_queue(completed_only=True),
            width=140
        ).grid(row=0, column=2, padx=5, pady=5)
        
        # Queue list
        self.queue_tree = ttk.Treeview(
            self.queue_frame,
            columns=("name", "target", "ports", "type", "status"),
            show="headings",
            height=4
        )
        
        self.queue_tree.heading("name", text="Name")
        self.queue_tree.heading("target", text="Target")
        self.queue_tree.heading("ports", text="Ports")
        self.queue_tree.heading("type", text="Scan Type")
        self.queue_tree.heading("status", text="Status")
        
        self.queue_tree.column("name", width=150)
        self.queue_tree.column("target", width=200)
        self.queue_tree.column("ports", width=100)
        self.queue_tree.column("type", width=100)
        self.queue_tree.column("status", width=100)
        
        self.queue_tree.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        # Apply dark theme
        style = ttk.Style()
        style.configure("Queue.Treeview", background="#2b2b2b", foreground="white",
                       fieldbackground="#2b2b2b")
        self.queue_tree.configure(style="Queue.Treeview")
        
        # Initially hide queue section
        self.queue_visible = False
        self.queue_frame.grid_remove()
    
    def _build_results_section(self):
        """Build the results display section"""
        results_frame = ctk.CTkFrame(self)
        results_frame.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(1, weight=1)
        
        # Title and filter bar
        title_frame = ctk.CTkFrame(results_frame)
        title_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        title_frame.grid_columnconfigure(2, weight=1)
        
        ctk.CTkLabel(title_frame, text="Scan Results", font=("Arial", 16, "bold")).grid(row=0, column=0, padx=10, pady=5)
        
        # Quick filter buttons
        quick_filter_frame = ctk.CTkFrame(title_frame)
        quick_filter_frame.grid(row=0, column=1, padx=10, pady=5)
        
        ctk.CTkButton(quick_filter_frame, text="All", command=lambda: self._quick_filter("all"), width=60).grid(row=0, column=0, padx=2)
        ctk.CTkButton(quick_filter_frame, text="Open", command=lambda: self._quick_filter("open"), width=60, fg_color="green").grid(row=0, column=1, padx=2)
        ctk.CTkButton(quick_filter_frame, text="Closed", command=lambda: self._quick_filter("closed"), width=60, fg_color="red").grid(row=0, column=2, padx=2)
        
        # Filter controls
        self.filter_entry = ctk.CTkEntry(title_frame, placeholder_text="🔍 Search...", width=200)
        self.filter_entry.grid(row=0, column=2, padx=10, pady=5, sticky="e")
        self.filter_entry.bind("<KeyRelease>", self._apply_filter)
        
        self.state_filter_var = ctk.StringVar(value="all")
        state_filter = ctk.CTkComboBox(
            title_frame,
            variable=self.state_filter_var,
            values=["all", "open", "closed", "filtered"],
            command=lambda x: self._apply_filter(),
            width=120
        )
        state_filter.grid(row=0, column=3, padx=5, pady=5)
        
        ctk.CTkButton(title_frame, text="✖ Clear", command=self._clear_filters, width=80).grid(row=0, column=4, padx=5, pady=5)
        
        # Results treeview
        tree_frame = ctk.CTkFrame(results_frame)
        tree_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        
        self.results_tree = ttk.Treeview(
            tree_frame,
            columns=("host", "port", "state", "service", "banner"),
            show="headings",
            selectmode="extended"
        )
        
        self.results_tree.heading("host", text="Host")
        self.results_tree.heading("port", text="Port")
        self.results_tree.heading("state", text="State")
        self.results_tree.heading("service", text="Service")
        self.results_tree.heading("banner", text="Banner")
        
        self.results_tree.column("host", width=150)
        self.results_tree.column("port", width=80)
        self.results_tree.column("state", width=100)
        self.results_tree.column("service", width=150)
        self.results_tree.column("banner", width=300)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.results_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # Apply theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white",
                       fieldbackground="#2b2b2b", borderwidth=0)
        style.map("Treeview", background=[("selected", "#1f538d")])
        style.configure("Treeview.Heading", background="#1f1f1f", foreground="white", borderwidth=1)
        
        self.results_tree.tag_configure("open", foreground="#00ff00")
        self.results_tree.tag_configure("closed", foreground="#ff6666")
        self.results_tree.tag_configure("filtered", foreground="#ffaa00")
        
        self.results_tree.bind("<Double-1>", self._on_result_double_click)
        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_select)
    
    def _build_details_panel(self):
        """Build the details panel (right sidebar)"""
        self.details_frame = ctk.CTkFrame(self, width=300)
        self.details_frame.grid(row=0, column=1, rowspan=3, padx=(0, 10), pady=10, sticky="nsew")
        self.details_frame.grid_propagate(False)
        
        # Title
        title_frame = ctk.CTkFrame(self.details_frame)
        title_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(title_frame, text="Port Details", font=("Arial", 14, "bold")).pack(side="left", padx=10, pady=5)
        
        ctk.CTkButton(
            title_frame,
            text="✖",
            command=self._toggle_details_panel,
            width=30,
            height=30
        ).pack(side="right", padx=5, pady=5)
        
        # Details text widget
        import tkinter as tk
        self.details_text = tk.Text(
            self.details_frame,
            bg="#2b2b2b",
            fg="white",
            font=("Courier", 10),
            wrap="word",
            state="disabled"
        )
        self.details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Copy button
        ctk.CTkButton(
            self.details_frame,
            text="📋 Copy Details",
            command=self._copy_details
        ).pack(pady=5)
        
        # Initially show details panel
        self.details_visible = True
    
    def _build_status_bar(self):
        """Build the status bar"""
        status_frame = ctk.CTkFrame(self, height=60)
        status_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=(5, 10), sticky="ew")
        status_frame.grid_columnconfigure(1, weight=1)
        
        self.progress_bar = ctk.CTkProgressBar(status_frame, width=300)
        self.progress_bar.grid(row=0, column=0, padx=10, pady=5)
        self.progress_bar.set(0)
        
        self.status_label = ctk.CTkLabel(status_frame, text="Ready", anchor="w")
        self.status_label.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        
        self.stats_label = ctk.CTkLabel(status_frame, text="Results: 0 | Time: 0s", anchor="e")
        self.stats_label.grid(row=0, column=2, padx=10, pady=5)
    
    # ===== FEATURE SETUP =====
    
    def _setup_quick_actions(self):
        """Setup quick actions"""
        self.quick_actions.register_action("copy_ip", self._copy_selected_ip, "Ctrl+C")
        self.quick_actions.register_action("copy_port", self._copy_selected_port)
        self.quick_actions.register_action("rescan", self._rescan_selected, "F5")
        self.quick_actions.register_action("export_selected", self._export_selected, "Ctrl+Shift+E")
    
    def _setup_context_menu(self):
        """Setup right-click context menu"""
        from tkinter import Menu
        
        self.context_menu = Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy IP", command=self._copy_selected_ip)
        self.context_menu.add_command(label="Copy Port", command=self._copy_selected_port)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Rescan Port", command=self._rescan_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Export Selected", command=self._export_selected)
        
        self.results_tree.bind("<Button-3>", self._show_context_menu)
    
    def _setup_drag_drop(self):
        """Setup drag and drop"""
        try:
            self.target_entry.drop_target_register(DND_FILES)
            self.target_entry.dnd_bind('<<Drop>>', self._on_drop)
        except Exception as e:
            print(f"Drag & Drop setup error: {e}")
    
    def _on_drop(self, event):
        """Handle file drop"""
        files = self.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            if file_path.endswith('.txt'):
                self._load_targets_from_file(file_path)
            else:
                messagebox.showwarning("Invalid File", "Please drop a .txt file")
        return event.action
    
    # ===== RECOVERY =====
    
    def _check_recovery(self):
        """Check for recovery data on startup"""
        if self.recovery_manager.has_recovery_data():
            info = self.recovery_manager.get_recovery_info()
            if info:
                response = messagebox.askyesno(
                    "Recovery Available",
                    f"A previous session was found from {info['timestamp']}.\n\n"
                    "Would you like to restore it?"
                )
                
                if response:
                    self._restore_from_recovery()
                else:
                    self.recovery_manager.clear_recovery_data()
    
    def _restore_from_recovery(self):
        """Restore from recovery data"""
        data = self.recovery_manager.load_recovery_data()
        if data:
            # Restore results
            results = data.get("results", [])
            for result in results:
                self._add_result_to_tree(result)
            
            self.notification_manager.notify(
                "Recovery Complete",
                f"Restored {len(results)} scan results"
            )
            
            self.recovery_manager.clear_recovery_data()
    
    def _get_recovery_data(self) -> Dict:
        """Get data for recovery save"""
        return {
            "results": self.scan_results,
            "target": self.target_entry.get(),
            "is_scanning": self.is_scanning
        }
    
    # ===== QUEUE METHODS =====
    
    def _add_to_queue(self):
        """Add current config to queue"""
        from tkinter import simpledialog
        
        name = simpledialog.askstring("Queue Job", "Enter job name:", 
                                     initialvalue=f"Scan {len(self.queue_manager.get_all_jobs()) + 1}")
        if not name:
            return
        
        job_config = {
            "name": name,
            "target": self.target_entry.get(),
            "port_mode": self.port_mode_var.get(),
            "scan_type": self.scan_type_var.get(),
            "threads": self.threads_var.get(),
            "service_detection": self.service_detection_var.get()
        }
        
        job_id = self.queue_manager.add_job(job_config)
        self._refresh_queue_display()
        
        messagebox.showinfo("Success", f"Added '{name}' to queue")
        
        # Show queue panel if hidden
        if not self.queue_visible:
            self._toggle_queue_panel()
    
    def _execute_queue(self):
        """Execute all pending jobs in queue"""
        pending = self.queue_manager.get_pending_jobs()
        if not pending:
            messagebox.showinfo("Queue Empty", "No pending jobs in queue")
            return
        
        if self.is_scanning:
            messagebox.showwarning("Scan Running", "Please wait for current scan to complete")
            return
        
        # Start first job
        self._execute_next_queue_job()
    
    def _execute_next_queue_job(self):
        """Execute next job in queue"""
        pending = self.queue_manager.get_pending_jobs()
        if not pending:
            self.notification_manager.notify("Queue Complete", "All queued scans finished")
            self._refresh_queue_display()
            return
        
        job = pending[0]
        self.current_queue_job_id = job["id"]
        
        # Load job config
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, job["target"])
        self.port_mode_var.set(job["port_mode"])
        self.scan_type_var.set(job["scan_type"])
        self.threads_var.set(job["threads"])
        self.service_detection_var.set(job["service_detection"])
        
        # Update job status
        self.queue_manager.update_job_status(job["id"], "running")
        self._refresh_queue_display()
        
        # Start scan
        self._start_scan(from_queue=True)
    
    def _on_queue_scan_complete(self):
        """Handle queue scan completion"""
        if self.current_queue_job_id is not None:
            self.queue_manager.update_job_status(
                self.current_queue_job_id,
                "complete",
                len(self.scan_results)
            )
            self.current_queue_job_id = None
            self._refresh_queue_display()
            
            # Execute next job
            self._execute_next_queue_job()
    
    def _refresh_queue_display(self):
        """Refresh queue display"""
        # Clear tree
        for item in self.queue_tree.get_children():
            self.queue_tree.delete(item)
        
        # Add jobs
        for job in self.queue_manager.get_all_jobs():
            self.queue_tree.insert("", "end", values=(
                job["name"],
                job["target"],
                job["port_mode"],
                job["scan_type"],
                job["status"]
            ))
    
    def _clear_queue(self, completed_only=False):
        """Clear queue"""
        if completed_only:
            self.queue_manager.clear_completed()
            messagebox.showinfo("Success", "Cleared completed jobs")
        else:
            if messagebox.askyesno("Confirm", "Clear entire queue?"):
                self.queue_manager.clear_all()
                messagebox.showinfo("Success", "Queue cleared")
        
        self._refresh_queue_display()
    
    def _show_queue_manager(self):
        """Show queue manager (just refresh display for now)"""
        self._refresh_queue_display()
        if not self.queue_visible:
            self._toggle_queue_panel()
    
    def _toggle_queue_panel(self):
        """Toggle queue panel visibility"""
        if self.queue_visible:
            self.queue_frame.grid_remove()
            self.queue_visible = False
        else:
            self.queue_frame.grid()
            self.queue_visible = True
            self._refresh_queue_display()
    
    # ===== DETAILS PANEL =====
    
    def _on_result_select(self, event):
        """Handle result selection"""
        if not self.config_manager.get("preferences.auto_open_details", True):
            return
        
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = self.results_tree.item(selection[0])
        values = item['values']
        
        # Find full result data
        result = None
        for r in self.scan_results:
            if r.get("host") == values[0] and r.get("port") == values[1]:
                result = r
                break
        
        if result:
            self._show_port_details(result)
    
    def _show_port_details(self, result: Dict):
        """Show port details in sidebar"""
        if not self.details_visible:
            self._toggle_details_panel()
        
        import tkinter as tk
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", tk.END)
        
        details = f"""
HOST INFORMATION
{'=' * 40}
IP Address: {result.get('host', 'unknown')}
Port: {result.get('port', 'unknown')}
State: {result.get('state', 'unknown')}
Service: {result.get('service', 'unknown')}
Scan Type: {result.get('scan_type', 'unknown')}

SERVICE BANNER
{'=' * 40}
{result.get('banner', 'No banner available')}

ADDITIONAL INFO
{'=' * 40}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Note: OS Detection and Vulnerability scanning
coming in future updates.
"""
        
        self.details_text.insert("1.0", details)
        self.details_text.config(state="disabled")
    
    def _copy_details(self):
        """Copy details to clipboard"""
        import tkinter as tk
        details = self.details_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(details)
        messagebox.showinfo("Success", "Details copied to clipboard")
    
    def _toggle_details_panel(self):
        """Toggle details panel"""
        if self.details_visible:
            self.details_frame.grid_remove()
            self.details_visible = False
        else:
            self.details_frame.grid()
            self.details_visible = True
    
    def _on_result_double_click(self, event):
        """Handle double-click on result"""
        self._on_result_select(event)
    
    # ===== CONTEXT MENU ACTIONS =====
    
    def _show_context_menu(self, event):
        """Show context menu"""
        # Select item under cursor
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def _copy_selected_ip(self):
        """Copy selected IP to clipboard"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            ip = item['values'][0]
            self.clipboard_clear()
            self.clipboard_append(ip)
            messagebox.showinfo("Copied", f"IP {ip} copied to clipboard")
    
    def _copy_selected_port(self):
        """Copy selected port to clipboard"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            port = item['values'][1]
            self.clipboard_clear()
            self.clipboard_append(str(port))
            messagebox.showinfo("Copied", f"Port {port} copied to clipboard")
    
    def _rescan_selected(self):
        """Rescan selected port"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            ip = item['values'][0]
            port = item['values'][1]
            
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, ip)
            self.port_mode_var.set("single")
            self._on_port_mode_changed("single")
            self.port_custom_entry.delete(0, "end")
            self.port_custom_entry.insert(0, str(port))
            
            messagebox.showinfo("Ready", f"Ready to rescan {ip}:{port}")
    
    def _export_selected(self):
        """Export selected results"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select results to export")
            return
        
        selected_results = []
        for item_id in selection:
            item = self.results_tree.item(item_id)
            values = item['values']
            for result in self.scan_results:
                if result.get("host") == values[0] and result.get("port") == values[1]:
                    selected_results.append(result)
                    break
        
        if selected_results:
            self._export_results_dialog(selected_results)
    
    # ===== SCAN CONTROL =====
    
    def _start_scan(self, from_queue=False):
        """Start scan"""
        target_input = self.target_entry.get().strip()
        if not target_input:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not from_queue:
            self.config_manager.add_recent_target(target_input)
        
        self.status_label.configure(text="Parsing targets...")
        targets = self.engine.parse_targets(target_input, self.threads_var.get())
        
        if not targets:
            messagebox.showerror("Error", "Could not parse targets")
            return
        
        port_mode = self.port_mode_var.get()
        ports = []
        
        if port_mode == "range":
            try:
                start = int(self.port_start_entry.get())
                end = int(self.port_end_entry.get())
                ports = self.engine.get_port_list(port_mode, len(targets), start, end, 
                                                  self.threads_var.get(), self.scan_type_var.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid port range")
                return
        elif port_mode == "single":
            custom_ports = self.port_custom_entry.get().strip()
            if not custom_ports:
                messagebox.showerror("Error", "Please enter port numbers")
                return
            ports = self.engine.get_port_list(port_mode, len(targets), 1, 65535,
                                             self.threads_var.get(), self.scan_type_var.get(),
                                             custom_ports)
        else:
            ports = self.engine.get_port_list(port_mode, len(targets), 1, 65535,
                                             self.threads_var.get(), self.scan_type_var.get())
        
        if not ports:
            messagebox.showerror("Error", "No ports to scan")
            return
        
        scan_config = {
            "targets": targets,
            "ports": ports,
            "scan_type": self.scan_type_var.get(),
            "threads": self.threads_var.get(),
            "service_detection": self.service_detection_var.get(),
            "os_detection": self.os_detection_var.get(),
            "timeout": 1.0
        }
        
        if not from_queue:
            self._clear_results()
        
        self.is_scanning = True
        self.scan_start_time = datetime.now()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        if not from_queue:
            self.profile_var.set("Custom")
        
        self.status_label.configure(
            text=f"Scanning {len(targets)} target(s) on {len(ports)} port(s)..."
        )
        
        self.engine.start_scan(
            scan_config,
            on_result=self._on_scan_result,
            on_complete=self._on_scan_complete,
            on_error=self._on_scan_error
        )
        
        self._update_scan_timer()
    
    def _stop_scan(self):
        """Stop scan"""
        self.engine.stop_scan()
        self.is_scanning = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="Scan stopped by user")
    
    def _on_scan_result(self, result: Dict):
        """Handle scan result"""
        self.result_queue.put(result)
    
    def _on_scan_complete(self):
        """Handle scan completion"""
        self.result_queue.put({"type": "complete"})
    
    def _on_scan_error(self, error: str):
        """Handle scan error"""
        self.result_queue.put({"type": "error", "message": error})
    
    def _process_result_queue(self):
        """Process result queue"""
        try:
            while True:
                result = self.result_queue.get_nowait()
                
                if result.get("type") == "progress":
                    progress = result.get("progress", 0) / 100.0
                    self.progress_bar.set(progress)
                    
                elif result.get("type") == "result":
                    self._add_result_to_tree(result)
                    
                elif result.get("type") == "complete":
                    self._finalize_scan()
                    
                elif result.get("type") == "error":
                    messagebox.showerror("Scan Error", result.get("message", "Unknown error"))
                    self._finalize_scan()
                    
        except queue.Empty:
            pass
        
        self.after(100, self._process_result_queue)
    
    def _add_result_to_tree(self, result: Dict):
        """Add result to tree"""
        self.scan_results.append(result)
        
        state = result.get("state", "unknown")
        banner = result.get("banner", "")
        display_banner = banner[:50] + "..." if len(banner) > 50 else banner
        
        item_id = self.results_tree.insert("", "end", values=(
            result.get("host", ""),
            result.get("port", ""),
            state,
            result.get("service", ""),
            display_banner
        ))
        
        if state == "open":
            self.results_tree.item(item_id, tags=("open",))
        elif state == "closed":
            self.results_tree.item(item_id, tags=("closed",))
        elif "filtered" in state:
            self.results_tree.item(item_id, tags=("filtered",))
        
        self._update_stats()
    
    def _finalize_scan(self):
        """Finalize scan"""
        self.is_scanning = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.progress_bar.set(1.0)
        self.status_label.configure(text="Scan complete")
        
        # Send notification
        if self.config_manager.get("preferences.show_notifications", True):
            open_count = sum(1 for r in self.scan_results if r.get("state") == "open")
            self.notification_manager.notify(
                "Scan Complete",
                f"Found {open_count} open ports",
                sound=self.config_manager.get("preferences.notification_sound", False)
            )
        
        # Handle queue
        if self.current_queue_job_id is not None:
            self._on_queue_scan_complete()
        
        self._save_settings()
    
    def _update_scan_timer(self):
        """Update scan timer"""
        if self.is_scanning and self.scan_start_time:
            elapsed = (datetime.now() - self.scan_start_time).total_seconds()
            self._update_stats(elapsed)
            self.after(1000, self._update_scan_timer)
    
    def _update_stats(self, elapsed: float = 0):
        """Update stats"""
        result_count = len(self.scan_results)
        open_count = sum(1 for r in self.scan_results if r.get("state") == "open")
        self.stats_label.configure(
            text=f"Results: {result_count} (Open: {open_count}) | Time: {int(elapsed)}s"
        )
    
    # ===== FILTER METHODS =====
    
    def _apply_filter(self, event=None):
        """Apply filters"""
        search_text = self.filter_entry.get().lower()
        state_filter = self.state_filter_var.get()
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        for result in self.scan_results:
            if state_filter != "all" and result.get("state", "").lower() != state_filter:
                continue
            
            if search_text:
                searchable = f"{result.get('host', '')} {result.get('port', '')} " \
                           f"{result.get('service', '')} {result.get('banner', '')}".lower()
                if search_text not in searchable:
                    continue
            
            state = result.get("state", "unknown")
            banner = result.get("banner", "")
            display_banner = banner[:50] + "..." if len(banner) > 50 else banner
            
            item_id = self.results_tree.insert("", "end", values=(
                result.get("host", ""),
                result.get("port", ""),
                state,
                result.get("service", ""),
                display_banner
            ))
            
            if state == "open":
                self.results_tree.item(item_id, tags=("open",))
            elif state == "closed":
                self.results_tree.item(item_id, tags=("closed",))
            elif "filtered" in state:
                self.results_tree.item(item_id, tags=("filtered",))
    
    def _quick_filter(self, filter_type: str):
        """Quick filter"""
        self.state_filter_var.set(filter_type)
        self._apply_filter()
    
    def _clear_filters(self):
        """Clear filters"""
        self.filter_entry.delete(0, "end")
        self.state_filter_var.set("all")
        self._apply_filter()
    
    def _clear_results(self):
        """Clear results"""
        self.scan_results.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.progress_bar.set(0)
        self._update_stats()
    
    # ===== EXPORT =====
    
    def _export_results_dialog(self, results=None):
        """Show export dialog"""
        if results is None:
            results = self.scan_results
        
        if not results:
            messagebox.showwarning("No Results", "No results to export")
            return
        
        ExportDialog(self, self.export_manager, results)
    
    # ===== UI HELPERS =====
    
    def _on_port_mode_changed(self, choice):
        """Handle port mode change"""
        if choice == "range":
            self.port_range_frame.grid(row=0, column=1, padx=5, pady=5)
            self.port_custom_frame.grid_forget()
        elif choice == "single":
            self.port_custom_frame.grid(row=0, column=1, padx=5, pady=5)
            self.port_range_frame.grid_forget()
        else:
            self.port_range_frame.grid_forget()
            self.port_custom_frame.grid_forget()
    
    def _update_thread_label(self, *args):
        """Update thread label"""
        self.threads_label.configure(text=str(self.threads_var.get()))
    
    # ===== PROFILE METHODS =====
    
    def _on_profile_selected(self, profile_name: str):
        """Load profile"""
        if profile_name == "Custom":
            return
        
        profile = self.profile_manager.get_profile(profile_name)
        if not profile:
            return
        
        self.port_mode_var.set(profile.get("port_mode", "common"))
        self.scan_type_var.set(profile.get("scan_type", "connect"))
        self.threads_var.set(profile.get("threads", 10))
        self.service_detection_var.set(profile.get("service_detection", False))
        self.os_detection_var.set(profile.get("os_detection", False))
        self.vuln_scan_var.set(profile.get("vuln_scan", False))
        
        self._on_port_mode_changed(profile.get("port_mode", "common"))
    
    def _save_current_as_profile(self):
        """Save current as profile"""
        from tkinter import simpledialog
        
        name = simpledialog.askstring("Save Profile", "Enter profile name:")
        if not name:
            return
        
        profile_config = {
            "description": f"Custom profile - {datetime.now().strftime('%Y-%m-%d')}",
            "port_mode": self.port_mode_var.get(),
            "scan_type": self.scan_type_var.get(),
            "threads": self.threads_var.get(),
            "service_detection": self.service_detection_var.get(),
            "os_detection": self.os_detection_var.get(),
            "vuln_scan": self.vuln_scan_var.get()
        }
        
        if self.profile_manager.create_profile(name, profile_config):
            messagebox.showinfo("Success", f"Profile '{name}' saved")
            self.profile_combo.configure(values=["Custom"] + self.profile_manager.list_profiles())
            self.profile_var.set(name)
        else:
            if messagebox.askyesno("Profile Exists", f"Profile '{name}' exists. Update?"):
                self.profile_manager.update_profile(name, profile_config)
                messagebox.showinfo("Success", f"Profile '{name}' updated")
                self.profile_var.set(name)
    
    def _manage_profiles(self):
        """Open profile manager"""
        ProfileManagerDialog(self, self.profile_manager, self.profile_combo, self.profile_var)
    
    # ===== FILE OPERATIONS =====
    
    def _show_recent_targets(self):
        """Show recent targets"""
        recent = self.config_manager.get_recent_targets()
        if not recent:
            messagebox.showinfo("No Recent Targets", "No recent targets")
            return
        
        from tkinter import Menu
        menu = Menu(self, tearoff=0)
        for target in recent[:10]:
            menu.add_command(label=target, command=lambda t=target: self._load_recent_target(t))
        
        menu.add_separator()
        menu.add_command(label="Clear Recent", command=self._clear_recent_targets)
        
        menu.post(self.recent_btn.winfo_rootx(), self.recent_btn.winfo_rooty() + 30)
    
    def _load_recent_target(self, target: str):
        """Load recent target"""
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, target)
    
    def _clear_recent_targets(self):
        """Clear recent targets"""
        self.config_manager.settings["recent_targets"] = []
        self.config_manager.save()
        messagebox.showinfo("Success", "Recent targets cleared")
    
    def _load_targets_file(self):
        """Load targets from file"""
        filename = filedialog.askopenfilename(
            title="Select Target File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            self._load_targets_from_file(filename)
    
    def _load_targets_from_file(self, filename: str):
        """Load targets from file"""
        try:
            with open(filename, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if targets:
                self.target_entry.delete(0, "end")
                self.target_entry.insert(0, " ".join(targets))
                messagebox.showinfo("Success", f"Loaded {len(targets)} target(s)")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load file: {e}")
    
    # ===== SETTINGS =====
    
    def _load_settings(self):
        """Load settings"""
        last_target = self.config_manager.get("last_scan.target", "")
        if last_target and self.config_manager.get("preferences.auto_save", True):
            self.target_entry.insert(0, last_target)
        
        self.port_mode_var.set(self.config_manager.get("last_scan.port_mode", "common"))
        self.scan_type_var.set(self.config_manager.get("last_scan.scan_type", "connect"))
        self.threads_var.set(self.config_manager.get("last_scan.threads", 10))
        self.service_detection_var.set(self.config_manager.get("last_scan.service_detection", True))
        
        # Notification settings
        self.notification_manager.set_enabled(
            self.config_manager.get("preferences.show_notifications", True)
        )
        self.notification_manager.set_sound_enabled(
            self.config_manager.get("preferences.notification_sound", False)
        )
    
    def _save_settings(self):
        """Save settings"""
        self.config_manager.set("window.width", self.winfo_width())
        self.config_manager.set("window.height", self.winfo_height())
        self.config_manager.set("window.x", self.winfo_x())
        self.config_manager.set("window.y", self.winfo_y())
        
        self.config_manager.set("last_scan.target", self.target_entry.get())
        self.config_manager.set("last_scan.port_mode", self.port_mode_var.get())
        self.config_manager.set("last_scan.scan_type", self.scan_type_var.get())
        self.config_manager.set("last_scan.threads", self.threads_var.get())
        self.config_manager.set("last_scan.service_detection", self.service_detection_var.get())
        
        self.config_manager.save()
    
    def _show_settings(self):
        """Show settings"""
        SettingsDialog(self, self.config_manager, self.notification_manager)
    
    # ===== MENU ACTIONS =====
    
    def _show_about(self):
        """Show about"""
        about_text = """PortPhantom v1.0
Professional Network Port Scanner

✅ Phase 1-5: Complete!

Features:
- Persistent Settings
- Drag & Drop Target Files
- Scan Profiles & Queue
- Advanced Filtering
- Details Panel
- Desktop Notifications
- Auto-Save & Recovery
- Quick Actions & Context Menus
- Enhanced Export (TXT/CSV/JSON/HTML)

Built with Python and CustomTkinter
Powered by scanner.py engine

Ready for Phase 6: Polish & Build!"""
        messagebox.showinfo("About PortPhantom", about_text)
    
    def _show_scapy_status(self):
        """Show Scapy status"""
        if self.engine.scapy_available:
            status = "✓ Scapy is installed\n\nAll scan types enabled."
        else:
            status = "✗ Scapy not installed\n\nOnly Connect scan available.\n\nInstall: pip install scapy"
        
        messagebox.showinfo("Scapy Status", status)
    
    def _show_shortcuts(self):
        """Show shortcuts"""
        shortcuts = """Keyboard Shortcuts:

File Operations:
Ctrl+O - Load targets
Ctrl+E - Export results
Ctrl+P - Manage profiles
Ctrl+Q - Manage queue
Ctrl+L - Clear results

Scanning:
F5 - Start scan
Esc - Stop scan

Filters:
Ctrl+0 - Show all results
Ctrl+1 - Show open only

View:
F9 - Toggle details panel
F10 - Toggle queue panel

Context Menu:
Right-click on results for quick actions"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
    
    def _on_closing(self):
        """Handle closing"""
        if self.is_scanning:
            if not messagebox.askyesno("Scan Running", "Stop scan and exit?"):
                return
            self.engine.stop_scan()
        
        self.recovery_manager.stop_auto_save()
        self._save_settings()
        self.destroy()


# ===== DIALOGS =====

class ProfileManagerDialog(ctk.CTkToplevel):
    """Profile manager dialog"""
    
    def __init__(self, parent, profile_manager, profile_combo, profile_var):
        super().__init__(parent)
        
        self.profile_manager = profile_manager
        self.profile_combo = profile_combo
        self.profile_var = profile_var
        
        self.title("Manage Profiles")
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()
        
        self._build_ui()
        self._refresh_list()
    
    def _build_ui(self):
        """Build UI"""
        import tkinter as tk
        
        list_frame = ctk.CTkFrame(self)
        list_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(list_frame, text="Saved Profiles", font=("Arial", 14, "bold")).pack(pady=5)
        
        self.profile_listbox = tk.Listbox(list_frame, bg="#2b2b2b", fg="white")
        self.profile_listbox.pack(fill="both", expand=True, pady=5)
        
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(side="right", fill="y", padx=10, pady=10)
        
        ctk.CTkButton(button_frame, text="Delete", command=self._delete_profile,
                     fg_color="red").pack(pady=5, fill="x")
        ctk.CTkButton(button_frame, text="Load", command=self._load_profile).pack(pady=5, fill="x")
        ctk.CTkButton(button_frame, text="Close", command=self.destroy).pack(pady=5, fill="x")
    
    def _refresh_list(self):
        """Refresh list"""
        import tkinter as tk
        self.profile_listbox.delete(0, tk.END)
        for name in self.profile_manager.list_profiles():
            self.profile_listbox.insert(tk.END, name)
    
    def _delete_profile(self):
        """Delete profile"""
        import tkinter as tk
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a profile")
            return
        
        name = self.profile_listbox.get(selection[0])
        
        if messagebox.askyesno("Confirm", f"Delete '{name}'?"):
            self.profile_manager.delete_profile(name)
            self._refresh_list()
            self.profile_combo.configure(values=["Custom"] + self.profile_manager.list_profiles())
    
    def _load_profile(self):
        """Load profile"""
        import tkinter as tk
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a profile")
            return
        
        name = self.profile_listbox.get(selection[0])
        self.profile_var.set(name)
        self.destroy()


class SettingsDialog(ctk.CTkToplevel):
    """Settings dialog"""
    
    def __init__(self, parent, config_manager, notification_manager):
        super().__init__(parent)
        
        self.config_manager = config_manager
        self.notification_manager = notification_manager
        
        self.title("Settings")
        self.geometry("500x500")
        self.transient(parent)
        self.grab_set()
        
        self._build_ui()
    
    def _build_ui(self):
        """Build UI"""
        main_frame = ctk.CTkScrollableFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="Preferences", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Auto-save
        self.auto_save_var = ctk.BooleanVar(value=self.config_manager.get("preferences.auto_save", True))
        ctk.CTkCheckBox(main_frame, text="Auto-save configuration", variable=self.auto_save_var).pack(pady=5, anchor="w")
        
        # Remember filters
        self.remember_filters_var = ctk.BooleanVar(value=self.config_manager.get("preferences.remember_filters", True))
        ctk.CTkCheckBox(main_frame, text="Remember filter settings", variable=self.remember_filters_var).pack(pady=5, anchor="w")
        
        # Auto-open details
        self.auto_open_details_var = ctk.BooleanVar(value=self.config_manager.get("preferences.auto_open_details", True))
        ctk.CTkCheckBox(main_frame, text="Auto-open details panel", variable=self.auto_open_details_var).pack(pady=5, anchor="w")
        
        # Notifications
        ctk.CTkLabel(main_frame, text="Notifications", font=("Arial", 14, "bold")).pack(pady=(20, 10))
        
        self.show_notifications_var = ctk.BooleanVar(value=self.config_manager.get("preferences.show_notifications", True))
        ctk.CTkCheckBox(main_frame, text="Show desktop notifications", variable=self.show_notifications_var).pack(pady=5, anchor="w")
        
        self.notification_sound_var = ctk.BooleanVar(value=self.config_manager.get("preferences.notification_sound", False))
        ctk.CTkCheckBox(main_frame, text="Play notification sound", variable=self.notification_sound_var).pack(pady=5, anchor="w")
        
        # Theme
        ctk.CTkLabel(main_frame, text="Appearance", font=("Arial", 14, "bold")).pack(pady=(20, 10))
        
        ctk.CTkLabel(main_frame, text="Theme:").pack(pady=5, anchor="w")
        self.theme_var = ctk.StringVar(value=self.config_manager.get("theme", "dark"))
        ctk.CTkComboBox(main_frame, variable=self.theme_var, values=["dark", "light"], width=200).pack(pady=5, anchor="w")
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(side="bottom", pady=20)
        
        ctk.CTkButton(button_frame, text="Save", command=self._save).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Cancel", command=self.destroy).pack(side="left", padx=5)
    
    def _save(self):
        """Save settings"""
        self.config_manager.set("preferences.auto_save", self.auto_save_var.get())
        self.config_manager.set("preferences.remember_filters", self.remember_filters_var.get())
        self.config_manager.set("preferences.auto_open_details", self.auto_open_details_var.get())
        self.config_manager.set("preferences.show_notifications", self.show_notifications_var.get())
        self.config_manager.set("preferences.notification_sound", self.notification_sound_var.get())
        self.config_manager.set("theme", self.theme_var.get())
        self.config_manager.save()
        
        # Update notification manager
        self.notification_manager.set_enabled(self.show_notifications_var.get())
        self.notification_manager.set_sound_enabled(self.notification_sound_var.get())
        
        messagebox.showinfo("Success", "Settings saved! Restart for theme changes.")
        self.destroy()


class ExportDialog(ctk.CTkToplevel):
    """Export dialog"""
    
    def __init__(self, parent, export_manager, results):
        super().__init__(parent)
        
        self.export_manager = export_manager
        self.results = results
        
        self.title("Export Results")
        self.geometry("400x300")
        self.transient(parent)
        self.grab_set()
        
        self._build_ui()
    
    def _build_ui(self):
        """Build UI"""
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="Export Options", font=("Arial", 16, "bold")).pack(pady=10)
        
        ctk.CTkLabel(main_frame, text=f"Exporting {len(self.results)} results").pack(pady=5)
        
        # Format selection
        ctk.CTkLabel(main_frame, text="Format:", font=("Arial", 12, "bold")).pack(pady=(20, 5), anchor="w")
        
        self.format_var = ctk.StringVar(value="txt")
        ctk.CTkRadioButton(main_frame, text="Text (.txt)", variable=self.format_var, value="txt").pack(pady=2, anchor="w")
        ctk.CTkRadioButton(main_frame, text="CSV (.csv)", variable=self.format_var, value="csv").pack(pady=2, anchor="w")
        ctk.CTkRadioButton(main_frame, text="JSON (.json)", variable=self.format_var, value="json").pack(pady=2, anchor="w")
        ctk.CTkRadioButton(main_frame, text="HTML (.html)", variable=self.format_var, value="html").pack(pady=2, anchor="w")
        
        # Metadata option
        self.include_metadata_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(main_frame, text="Include metadata", variable=self.include_metadata_var).pack(pady=10)
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(side="bottom", pady=10)
        
        ctk.CTkButton(button_frame, text="Export", command=self._export, fg_color="green").pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Cancel", command=self.destroy).pack(side="left", padx=5)
    
    def _export(self):
        """Perform export"""
        format_type = self.format_var.get()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.{format_type}"
        
        success = False
        
        if format_type == "txt":
            success = self.export_manager.export_txt(
                self.results, filename, self.include_metadata_var.get()
            )
        elif format_type == "csv":
            success = self.export_manager.export_csv(self.results, filename)
        elif format_type == "json":
            success = self.export_manager.export_json(
                self.results, filename, self.include_metadata_var.get()
            )
        elif format_type == "html":
            success = self.export_manager.export_html(self.results, filename)
        
        if success:
            filepath = self.export_manager.get_export_path(filename)
            
            if messagebox.askyesno("Export Complete", 
                                  f"Results exported to:\n{filepath}\n\nOpen file?"):
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(filepath)
                    elif os.name == 'posix':  # macOS/Linux
                        os.system(f'open "{filepath}"')
                except:
                    webbrowser.open(f"file://{filepath}")
            
            self.destroy()
        else:
            messagebox.showerror("Error", "Export failed")


def main():
    """Main entry point"""
    app = PortPhantomGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
