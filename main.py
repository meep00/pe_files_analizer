import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pefile
import os
import hashlib
from datetime import datetime


class PEAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PE File Analyzer")
        self.root.geometry("1000x700")

        # Style configuration
        style = ttk.Style()
        style.configure("Header.TLabel", font=('Helvetica', 10, 'bold'))

        # Main container
        self.main_frame = ttk.Frame(root, padding="5")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_file_section()
        self._create_notebook()
        self._create_status_bar()

    def _create_file_section(self):
        """Create file selection section"""
        file_frame = ttk.LabelFrame(self.main_frame, text="File Selection", padding="5")
        file_frame.pack(fill=tk.X, padx=5, pady=5)

        # File path entry and browse button
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=70).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Browse", command=self._browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Analyze", command=self._analyze_file).pack(side=tk.LEFT, padx=5)

    def _create_notebook(self):
        """Create notebook with different analysis tabs"""
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create various tabs
        self.general_tab = ttk.Frame(self.notebook)
        self.headers_tab = ttk.Frame(self.notebook)
        self.sections_tab = ttk.Frame(self.notebook)
        self.imports_tab = ttk.Frame(self.notebook)
        self.security_tab = ttk.Frame(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.general_tab, text="General Info")
        self.notebook.add(self.headers_tab, text="PE Headers")
        self.notebook.add(self.sections_tab, text="Sections")
        self.notebook.add(self.imports_tab, text="Imports")
        self.notebook.add(self.security_tab, text="Security Analysis")

        # Create text widgets for each tab
        self.general_text = self._create_text_widget(self.general_tab)
        self.headers_text = self._create_text_widget(self.headers_tab)
        self.sections_text = self._create_text_widget(self.sections_tab)
        self.imports_text = self._create_text_widget(self.imports_tab)
        self.security_text = self._create_text_widget(self.security_tab)

    def _create_text_widget(self, parent):
        """Create scrollable text widget"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)

        text_widget = tk.Text(frame, wrap=tk.NONE, font=('Courier', 10))
        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text_widget.xview)

        text_widget.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        return text_widget

    def _create_status_bar(self):
        """Create status bar"""
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _browse_file(self):
        """Open file browser dialog"""
        filename = filedialog.askopenfilename(
            title="Select PE file",
            filetypes=(
                ("Executable files", "*.exe;*.dll;*.sys"),
                ("All files", "*.*")
            )
        )
        if filename:
            self.file_path.set(filename)

    def _analyze_file(self):
        """Analyze selected PE file"""
        try:
            file_path = self.file_path.get()
            if not file_path:
                messagebox.showerror("Error", "Please select a file first")
                return

            self.status_var.set("Analyzing file...")
            self.root.update()

            pe = pefile.PE(file_path)

            # Clear all text widgets
            for widget in [self.general_text, self.headers_text, self.sections_text,
                           self.imports_text, self.security_text]:
                widget.delete(1.0, tk.END)

            # Analyze and display results
            self._analyze_general_info(file_path, pe)
            self._analyze_headers(pe)
            self._analyze_sections(pe)
            self._analyze_imports(pe)
            self._analyze_security(pe)

            self.status_var.set("Analysis completed")

        except Exception as e:
            self.status_var.set("Analysis failed")
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")

    def _analyze_general_info(self, file_path, pe):
        """Analyze and display general file information"""
        file_info = {
            "File Name": os.path.basename(file_path),
            "File Size": f"{os.path.getsize(file_path):,} bytes",
            "MD5": self._calculate_hash(file_path, 'md5'),
            "SHA-1": self._calculate_hash(file_path, 'sha1'),
            "SHA-256": self._calculate_hash(file_path, 'sha256'),
            "Creation Time": datetime.fromtimestamp(os.path.getctime(file_path)),
            "Last Modified": datetime.fromtimestamp(os.path.getmtime(file_path))
        }

        self.general_text.insert(tk.END, "=== General Information ===\n\n")
        for key, value in file_info.items():
            self.general_text.insert(tk.END, f"{key}: {value}\n")

    def _analyze_headers(self, pe):
        """Analyze and display PE headers"""
        # DOS Header
        self.headers_text.insert(tk.END, "=== DOS Header ===\n\n")
        dos_header_items = [
            ('e_magic', 'Magic number'),
            ('e_lfanew', 'File address of new exe header'),
            ('e_cblp', 'Bytes on last page of file'),
            ('e_cp', 'Pages in file'),
            ('e_crlc', 'Relocations'),
            ('e_cparhdr', 'Size of header in paragraphs'),
            ('e_minalloc', 'Minimum extra paragraphs needed'),
            ('e_maxalloc', 'Maximum extra paragraphs needed'),
            ('e_ss', 'Initial (relative) SS value'),
            ('e_sp', 'Initial SP value'),
            ('e_ip', 'Initial IP value'),
            ('e_cs', 'Initial (relative) CS value'),
            ('e_lfarlc', 'File address of relocation table'),
            ('e_ovno', 'Overlay number')
        ]

        for field, description in dos_header_items:
            if hasattr(pe.DOS_HEADER, field):
                value = getattr(pe.DOS_HEADER, field)
                self.headers_text.insert(tk.END, f"{description}: {hex(value)}\n")

        # File Header
        self.headers_text.insert(tk.END, "\n=== File Header ===\n\n")
        file_header_items = [
            ('Machine', 'Target machine'),
            ('NumberOfSections', 'Number of sections'),
            ('TimeDateStamp', 'Time date stamp'),
            ('PointerToSymbolTable', 'Pointer to symbol table'),
            ('NumberOfSymbols', 'Number of symbols'),
            ('SizeOfOptionalHeader', 'Size of optional header'),
            ('Characteristics', 'Characteristics')
        ]

        for field, description in file_header_items:
            if hasattr(pe.FILE_HEADER, field):
                value = getattr(pe.FILE_HEADER, field)
                if field == 'TimeDateStamp':
                    try:
                        timestamp = datetime.fromtimestamp(value)
                        self.headers_text.insert(tk.END, f"{description}: {timestamp} ({hex(value)})\n")
                    except:
                        self.headers_text.insert(tk.END, f"{description}: {hex(value)}\n")
                else:
                    self.headers_text.insert(tk.END, f"{description}: {hex(value)}\n")

    def _analyze_sections(self, pe):
        """Analyze and display section information"""
        self.sections_text.insert(tk.END, "=== Section Headers ===\n\n")
        for section in pe.sections:
            self.sections_text.insert(tk.END, f"Section: {section.Name.decode().rstrip('\x00')}\n")
            self.sections_text.insert(tk.END, f"Virtual Address: {hex(section.VirtualAddress)}\n")
            self.sections_text.insert(tk.END, f"Virtual Size: {hex(section.Misc_VirtualSize)}\n")
            self.sections_text.insert(tk.END, f"Raw Size: {hex(section.SizeOfRawData)}\n")
            self.sections_text.insert(tk.END, f"Characteristics: {hex(section.Characteristics)}\n\n")

    def _analyze_imports(self, pe):
        """Analyze and display import information"""
        try:
            self.imports_text.insert(tk.END, "=== Imported DLLs and Functions ===\n\n")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                self.imports_text.insert(tk.END, f"DLL: {entry.dll.decode()}\n")
                for imp in entry.imports:
                    if imp.name:
                        self.imports_text.insert(tk.END, f"\t{imp.name.decode()}\n")
                self.imports_text.insert(tk.END, "\n")
        except AttributeError:
            self.imports_text.insert(tk.END, "No imports found or unable to parse import directory.\n")

    def _analyze_security(self, pe):
        """Analyze and display security-related information"""
        security_info = []

        # Check for suspicious section names
        suspicious_sections = ['.upx', '.packed', '.compress']
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00')
            if any(susp in name.lower() for susp in suspicious_sections):
                security_info.append(f"WARNING: Potentially suspicious section found: {name}")

        # Check for high entropy (possible packing/encryption)
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.0:
                name = section.Name.decode().rstrip('\x00')
                security_info.append(f"WARNING: High entropy ({entropy:.2f}) in section {name}")

        # Check for ASLR, DEP, and other security features
        if hasattr(pe, 'OPTIONAL_HEADER'):
            characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
            if not characteristics & 0x0040:
                security_info.append("WARNING: ASLR is not enabled")
            if not characteristics & 0x0100:
                security_info.append("WARNING: DEP is not enabled")

        self.security_text.insert(tk.END, "=== Security Analysis ===\n\n")
        if security_info:
            for info in security_info:
                self.security_text.insert(tk.END, f"{info}\n")
        else:
            self.security_text.insert(tk.END, "No immediate security concerns found.\n")

    def _calculate_hash(self, file_path, hash_type):
        """Calculate file hash"""
        hash_func = getattr(hashlib, hash_type)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()


def main():
    root = tk.Tk()
    app = PEAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()