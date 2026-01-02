#!/usr/bin/env python3
"""
Veriduct Prime GUI
A graphical interface for the Veriduct format destruction framework.

Features:
- Annihilate files/directories with configurable options
- Reassemble files from chunks
- Run semantic execution
- Real-time log output
- Progress tracking

Author: Bombadil Systems LLC
"""

import os
import sys
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import logging
from datetime import datetime

# Import veriduct_prime module - adjust path as needed
try:
    import veriduct_prime
except ImportError:
    # Try to find it in common locations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for path in [script_dir, os.getcwd()]:
        prime_path = os.path.join(path, 'veriduct_prime.py')
        if os.path.exists(prime_path):
            import importlib.util
            spec = importlib.util.spec_from_file_location("veriduct_prime", prime_path)
            veriduct_prime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(veriduct_prime)
            break
    else:
        veriduct_prime = None


class QueueHandler(logging.Handler):
    """Custom logging handler that puts log records into a queue."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))


class VeriductGUI:
    """Main GUI application for Veriduct Prime."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Veriduct Prime")
        self.root.geometry("900x750")
        self.root.minsize(800, 600)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Custom colors
        self.colors = {
            'bg': '#1a1a2e',
            'fg': '#eef0f2',
            'accent': '#16213e',
            'highlight': '#0f3460',
            'success': '#00bf63',
            'warning': '#ffc93c',
            'error': '#e94560',
            'text_bg': '#0d0d1a'
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Configure styles
        self._configure_styles()
        
        # Queue for log messages
        self.log_queue = queue.Queue()
        
        # Operation state
        self.operation_running = False
        self.current_thread = None
        
        # Build UI
        self._create_widgets()
        
        # Setup logging
        self._setup_logging()
        
        # Start log queue processor
        self._process_log_queue()
        
        # Log startup
        self.log_message("Veriduct Prime GUI initialized")
        self.log_message(f"Working directory: {os.getcwd()}")
        
        if veriduct_prime is None:
            self.log_message("WARNING: veriduct_prime module not found!", 'warning')
            self.log_message("Place veriduct_prime.py in the same directory as this GUI", 'warning')

    def _configure_styles(self):
        """Configure ttk styles for dark theme."""
        self.style.configure('.',
            background=self.colors['bg'],
            foreground=self.colors['fg'],
            fieldbackground=self.colors['accent']
        )
        
        self.style.configure('TFrame', background=self.colors['bg'])
        self.style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        self.style.configure('TLabelframe', background=self.colors['bg'], foreground=self.colors['fg'])
        self.style.configure('TLabelframe.Label', background=self.colors['bg'], foreground=self.colors['fg'])
        
        self.style.configure('TButton',
            background=self.colors['highlight'],
            foreground=self.colors['fg'],
            padding=(10, 5)
        )
        self.style.map('TButton',
            background=[('active', self.colors['accent']), ('disabled', '#333')]
        )
        
        self.style.configure('Accent.TButton',
            background=self.colors['success'],
            foreground='white',
            padding=(15, 8)
        )
        self.style.map('Accent.TButton',
            background=[('active', '#00a854'), ('disabled', '#555')]
        )
        
        self.style.configure('TCheckbutton',
            background=self.colors['bg'],
            foreground=self.colors['fg']
        )
        
        self.style.configure('TRadiobutton',
            background=self.colors['bg'],
            foreground=self.colors['fg']
        )
        
        self.style.configure('TCombobox',
            fieldbackground=self.colors['accent'],
            background=self.colors['accent'],
            foreground=self.colors['fg']
        )
        
        self.style.configure('TNotebook', background=self.colors['bg'])
        self.style.configure('TNotebook.Tab',
            background=self.colors['accent'],
            foreground=self.colors['fg'],
            padding=(15, 8)
        )
        self.style.map('TNotebook.Tab',
            background=[('selected', self.colors['highlight'])]
        )
        
        self.style.configure('TEntry',
            fieldbackground=self.colors['accent'],
            foreground=self.colors['fg']
        )
        
        self.style.configure('TSpinbox',
            fieldbackground=self.colors['accent'],
            foreground=self.colors['fg']
        )
        
        self.style.configure('Horizontal.TProgressbar',
            background=self.colors['success'],
            troughcolor=self.colors['accent']
        )

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(header_frame, 
            text="VERIDUCT PRIME",
            font=('Helvetica', 24, 'bold')
        )
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = ttk.Label(header_frame,
            text="Format Destruction Framework",
            font=('Helvetica', 10)
        )
        subtitle_label.pack(side=tk.LEFT, padx=(15, 0), pady=(12, 0))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self._create_annihilate_tab()
        self._create_reassemble_tab()
        self._create_run_tab()
        
        # Log output area
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame,
            height=12,
            bg=self.colors['text_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            font=('Consolas', 9),
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure log tags
        self.log_text.tag_configure('info', foreground=self.colors['fg'])
        self.log_text.tag_configure('success', foreground=self.colors['success'])
        self.log_text.tag_configure('warning', foreground=self.colors['warning'])
        self.log_text.tag_configure('error', foreground=self.colors['error'])
        self.log_text.tag_configure('timestamp', foreground='#666')
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress.pack(side=tk.RIGHT)
        
        # Clear log button
        clear_btn = ttk.Button(status_frame, text="Clear Log", command=self._clear_log)
        clear_btn.pack(side=tk.RIGHT, padx=(0, 10))

    def _create_annihilate_tab(self):
        """Create the Annihilate tab."""
        tab = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(tab, text="Annihilate")
        
        # Input section
        input_frame = ttk.LabelFrame(tab, text="Input", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(input_frame, text="Source Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.annihilate_input = ttk.Entry(input_frame, width=60)
        self.annihilate_input.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="File", command=lambda: self._browse_file(self.annihilate_input)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Dir", command=lambda: self._browse_dir(self.annihilate_input)).pack(side=tk.LEFT, padx=2)
        
        ttk.Label(input_frame, text="Output Dir:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.annihilate_output = ttk.Entry(input_frame, width=60)
        self.annihilate_output.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=lambda: self._browse_dir(self.annihilate_output)).grid(row=1, column=2, padx=5)
        
        input_frame.columnconfigure(1, weight=1)
        
        # Options section - two columns
        options_outer = ttk.Frame(tab)
        options_outer.pack(fill=tk.X, pady=(0, 10))
        
        # Left column - Basic options
        left_frame = ttk.LabelFrame(options_outer, text="Basic Options", padding="10")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        ttk.Label(left_frame, text="Wipe Bytes:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.wipe_bytes = ttk.Spinbox(left_frame, from_=0, to=4096, width=10)
        self.wipe_bytes.set(256)
        self.wipe_bytes.grid(row=0, column=1, sticky=tk.W, pady=3)
        
        ttk.Label(left_frame, text="Disguise Format:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.disguise_format = ttk.Combobox(left_frame, values=['None', 'csv', 'log', 'conf'], width=10, state='readonly')
        self.disguise_format.set('None')
        self.disguise_format.grid(row=1, column=1, sticky=tk.W, pady=3)
        
        self.no_hmac_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_frame, text="Disable HMAC", variable=self.no_hmac_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_frame, text="Verbose Output", variable=self.verbose_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        self.force_internal_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_frame, text="Force Internal", variable=self.force_internal_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        # Right column - Advanced options
        right_frame = ttk.LabelFrame(options_outer, text="Advanced Options", padding="10")
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.variable_chunks_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_frame, text="Variable Chunks", variable=self.variable_chunks_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        ttk.Label(right_frame, text="Chunk Jitter:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.chunk_jitter = ttk.Spinbox(right_frame, from_=0.0, to=0.5, increment=0.05, width=10)
        self.chunk_jitter.set(0.0)
        self.chunk_jitter.grid(row=1, column=1, sticky=tk.W, pady=3)
        
        self.ssm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_frame, text="Semantic Shatter Mapping (SSM)", variable=self.ssm_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        ttk.Label(right_frame, text="SSM Null Rate:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.ssm_null_rate = ttk.Spinbox(right_frame, from_=0.0, to=0.1, increment=0.01, width=10)
        self.ssm_null_rate.set(0.01)
        self.ssm_null_rate.grid(row=3, column=1, sticky=tk.W, pady=3)
        
        self.entanglement_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_frame, text="XOR Entanglement", variable=self.entanglement_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        ttk.Label(right_frame, text="Entangle Groups:").grid(row=5, column=0, sticky=tk.W, pady=3)
        self.entangle_groups = ttk.Spinbox(right_frame, from_=2, to=10, width=10)
        self.entangle_groups.set(3)
        self.entangle_groups.grid(row=5, column=1, sticky=tk.W, pady=3)
        
        self.fake_chunks_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_frame, text="Substrate Poisoning", variable=self.fake_chunks_var).grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        ttk.Label(right_frame, text="Fake Ratio:").grid(row=7, column=0, sticky=tk.W, pady=3)
        self.fake_ratio = ttk.Spinbox(right_frame, from_=0.0, to=1.0, increment=0.05, width=10)
        self.fake_ratio.set(0.25)
        self.fake_ratio.grid(row=7, column=1, sticky=tk.W, pady=3)
        
        # Execute button
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.annihilate_btn = ttk.Button(btn_frame, text="ANNIHILATE", style='Accent.TButton', command=self._run_annihilate)
        self.annihilate_btn.pack(side=tk.RIGHT)

    def _create_reassemble_tab(self):
        """Create the Reassemble tab."""
        tab = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(tab, text="Reassemble")
        
        # Input section
        input_frame = ttk.LabelFrame(tab, text="Input", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(input_frame, text="Keymap File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.reassemble_keymap = ttk.Entry(input_frame, width=60)
        self.reassemble_keymap.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=lambda: self._browse_file(self.reassemble_keymap)).grid(row=0, column=2, padx=5)
        
        ttk.Label(input_frame, text="Output Dir:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.reassemble_output = ttk.Entry(input_frame, width=60)
        self.reassemble_output.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=lambda: self._browse_dir(self.reassemble_output)).grid(row=1, column=2, padx=5)
        
        input_frame.columnconfigure(1, weight=1)
        
        # Options
        options_frame = ttk.LabelFrame(tab, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(options_frame, text="Disguise Format:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.reassemble_disguise = ttk.Combobox(options_frame, values=['None', 'csv', 'log', 'conf'], width=10, state='readonly')
        self.reassemble_disguise.set('None')
        self.reassemble_disguise.grid(row=0, column=1, sticky=tk.W, pady=3, padx=5)
        
        self.ignore_integrity_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Ignore Integrity Errors", variable=self.ignore_integrity_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        self.reassemble_verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Verbose Output", variable=self.reassemble_verbose_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        # Execute button
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.reassemble_btn = ttk.Button(btn_frame, text="REASSEMBLE", style='Accent.TButton', command=self._run_reassemble)
        self.reassemble_btn.pack(side=tk.RIGHT)

    def _create_run_tab(self):
        """Create the Run (Semantic Execution) tab."""
        tab = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(tab, text="Run")
        
        # Info banner
        info_frame = ttk.Frame(tab)
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        info_label = ttk.Label(info_frame,
            text="Execute files directly from chunks without disk materialization\nSupports: Python (.pyc/.py), PE (.exe/.dll), ELF",
            justify=tk.CENTER,
            font=('Helvetica', 9)
        )
        info_label.pack()
        
        # Input section
        input_frame = ttk.LabelFrame(tab, text="Input", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(input_frame, text="Keymap File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.run_keymap = ttk.Entry(input_frame, width=60)
        self.run_keymap.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=lambda: self._browse_file(self.run_keymap)).grid(row=0, column=2, padx=5)
        
        ttk.Label(input_frame, text="Arguments:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.run_args = ttk.Entry(input_frame, width=60)
        self.run_args.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(input_frame, text="(e.g., --exploit 1 --payload test)", 
                 foreground='#888', font=('Helvetica', 8)).grid(row=1, column=2, padx=5)
        
        input_frame.columnconfigure(1, weight=1)
        
        # Options
        options_frame = ttk.LabelFrame(tab, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(options_frame, text="Disguise Format:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.run_disguise = ttk.Combobox(options_frame, values=['None', 'csv', 'log', 'conf'], width=10, state='readonly')
        self.run_disguise.set('None')
        self.run_disguise.grid(row=0, column=1, sticky=tk.W, pady=3, padx=5)
        
        self.run_ignore_integrity_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Ignore Integrity Errors", variable=self.run_ignore_integrity_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        self.run_verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Verbose Output", variable=self.run_verbose_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=3)
        
        # Warning
        warning_frame = ttk.Frame(tab)
        warning_frame.pack(fill=tk.X, pady=(10, 0))
        
        warning_label = ttk.Label(warning_frame,
            text="⚠ Semantic execution runs code directly in memory. Only execute trusted files.",
            foreground=self.colors['warning'],
            font=('Helvetica', 9)
        )
        warning_label.pack()
        
        # Execute button
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.run_btn = ttk.Button(btn_frame, text="EXECUTE", style='Accent.TButton', command=self._run_execute)
        self.run_btn.pack(side=tk.RIGHT)

    def _setup_logging(self):
        """Configure logging to use the queue handler."""
        # Create handler
        handler = QueueHandler(self.log_queue)
        handler.setFormatter(logging.Formatter('%(message)s'))
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.DEBUG)

    def _process_log_queue(self):
        """Process messages from the log queue."""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self._append_log(message)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_log_queue)

    def _append_log(self, message, tag='info'):
        """Append message to log with timestamp and tag."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        
        # Determine tag based on content
        if '✓' in message or 'success' in message.lower() or 'complete' in message.lower():
            tag = 'success'
        elif 'warning' in message.lower() or '⚠' in message:
            tag = 'warning'
        elif 'error' in message.lower() or 'failed' in message.lower():
            tag = 'error'
        
        self.log_text.insert(tk.END, f"{message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def log_message(self, message, tag='info'):
        """Log a message directly."""
        self._append_log(message, tag)

    def _clear_log(self):
        """Clear the log output."""
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')

    def _browse_file(self, entry_widget):
        """Open file browser and set entry widget."""
        filepath = filedialog.askopenfilename()
        if filepath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filepath)

    def _browse_dir(self, entry_widget):
        """Open directory browser and set entry widget."""
        dirpath = filedialog.askdirectory()
        if dirpath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, dirpath)

    def _set_running(self, running):
        """Set operation running state."""
        self.operation_running = running
        
        if running:
            self.progress.start(10)
            self.status_var.set("Processing...")
            state = 'disabled'
        else:
            self.progress.stop()
            self.status_var.set("Ready")
            state = 'normal'
        
        # Toggle all action buttons
        for btn in [self.annihilate_btn, self.reassemble_btn, self.run_btn]:
            btn.configure(state=state)

    def _run_annihilate(self):
        """Run annihilation operation."""
        if veriduct_prime is None:
            messagebox.showerror("Error", "veriduct_prime module not loaded!")
            return
        
        input_path = self.annihilate_input.get().strip()
        output_dir = self.annihilate_output.get().strip()
        
        if not input_path:
            messagebox.showerror("Error", "Please specify an input path")
            return
        if not output_dir:
            messagebox.showerror("Error", "Please specify an output directory")
            return
        if not os.path.exists(input_path):
            messagebox.showerror("Error", f"Input path does not exist: {input_path}")
            return
        
        disguise = self.disguise_format.get()
        if disguise == 'None':
            disguise = None
        
        def operation():
            try:
                result = veriduct_prime.annihilate_path(
                    input_path=input_path,
                    out_dir=output_dir,
                    wipe_size=int(self.wipe_bytes.get()),
                    use_variable_chunks=self.variable_chunks_var.get(),
                    chunk_jitter=float(self.chunk_jitter.get()),
                    use_ssm=self.ssm_var.get(),
                    ssm_null_rate=float(self.ssm_null_rate.get()),
                    use_entanglement=self.entanglement_var.get(),
                    entanglement_group_size=int(self.entangle_groups.get()),
                    use_fake_chunks=self.fake_chunks_var.get(),
                    fake_ratio=float(self.fake_ratio.get()),
                    add_hmac=not self.no_hmac_var.get(),
                    disguise=disguise,
                    force_internal=self.force_internal_var.get(),
                    verbose=self.verbose_var.get()
                )
                
                self.root.after(0, lambda: self._set_running(False))
                
            except Exception as e:
                logging.error(f"Annihilation failed: {e}")
                self.root.after(0, lambda: self._set_running(False))
        
        self._set_running(True)
        self.current_thread = threading.Thread(target=operation, daemon=True)
        self.current_thread.start()

    def _run_reassemble(self):
        """Run reassembly operation."""
        if veriduct_prime is None:
            messagebox.showerror("Error", "veriduct_prime module not loaded!")
            return
        
        keymap_path = self.reassemble_keymap.get().strip()
        output_dir = self.reassemble_output.get().strip()
        
        if not keymap_path:
            messagebox.showerror("Error", "Please specify a keymap file")
            return
        if not output_dir:
            messagebox.showerror("Error", "Please specify an output directory")
            return
        if not os.path.exists(keymap_path):
            messagebox.showerror("Error", f"Keymap file does not exist: {keymap_path}")
            return
        
        disguise = self.reassemble_disguise.get()
        if disguise == 'None':
            disguise = None
        
        def operation():
            try:
                veriduct_prime.reassemble_path(
                    key_path=keymap_path,
                    out_dir=output_dir,
                    disguise=disguise,
                    ignore_integrity=self.ignore_integrity_var.get(),
                    verbose=self.reassemble_verbose_var.get()
                )
                self.root.after(0, lambda: self._set_running(False))
                
            except Exception as e:
                logging.error(f"Reassembly failed: {e}")
                self.root.after(0, lambda: self._set_running(False))
        
        self._set_running(True)
        self.current_thread = threading.Thread(target=operation, daemon=True)
        self.current_thread.start()

    def _run_execute(self):
        """Run semantic execution operation."""
        if veriduct_prime is None:
            messagebox.showerror("Error", "veriduct_prime module not loaded!")
            return
        
        keymap_path = self.run_keymap.get().strip()
        
        if not keymap_path:
            messagebox.showerror("Error", "Please specify a keymap file")
            return
        if not os.path.exists(keymap_path):
            messagebox.showerror("Error", f"Keymap file does not exist: {keymap_path}")
            return
        
        # Confirm execution
        if not messagebox.askyesno("Confirm Execution", 
            "This will execute code directly in memory.\n\nAre you sure you want to proceed?"):
            return
        
        disguise = self.run_disguise.get()
        if disguise == 'None':
            disguise = None
        
        # Get arguments
        args = self.run_args.get().strip() if self.run_args.get().strip() else None
        
        def operation():
            try:
                veriduct_prime.run_annihilated_path(
                    key_path=keymap_path,
                    disguise=disguise,
                    ignore_integrity=self.run_ignore_integrity_var.get(),
                    verbose=self.run_verbose_var.get(),
                    command_line=args
                )
                self.root.after(0, lambda: self._set_running(False))
                
            except Exception as e:
                logging.error(f"Execution failed: {e}")
                self.root.after(0, lambda: self._set_running(False))
        
        self._set_running(True)
        self.current_thread = threading.Thread(target=operation, daemon=True)
        self.current_thread.start()


def main():
    """Main entry point."""
    root = tk.Tk()
    
    # Set icon if available
    try:
        # Could set a custom icon here
        pass
    except:
        pass
    
    app = VeriductGUI(root)
    
    # Handle window close
    def on_closing():
        if app.operation_running:
            if messagebox.askokcancel("Quit", "An operation is running. Are you sure you want to quit?"):
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
