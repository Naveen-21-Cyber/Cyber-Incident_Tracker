import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import os
from tkinter import ttk
from tkcalendar import DateEntry

class SecurityIncidentTracker:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Incident Tracker")
        self.root.geometry("950x650")
        self.root.configure(bg="#ffffff")  # Dark theme for cybersecurity feel
        
        # Initialize database
        self.conn = self.init_database()
        
        # Incident categories
        self.categories = [
            "Malware", "Phishing", "Data Breach", "DDoS", 
            "Unauthorized Access", "Insider Threat", "Social Engineering", "Ransomware", 
            "Zero-day Exploit", "Network Intrusion", "Physical Security", "Other"
        ]
        
        # Severity levels
        self.severity_levels = ["Critical", "High", "Medium", "Low", "Informational"]
        
        # Status options
        self.status_options = ["Open", "Investigating", "Contained", "Resolved", "Closed"]
        
        # Variables
        self.severity_var = tk.StringVar()
        self.severity_var.set(self.severity_levels[2])  # Default to Medium
        self.category_var = tk.StringVar()
        self.category_var.set(self.categories[0])
        self.description_var = tk.StringVar()
        self.date_var = tk.StringVar()
        self.date_var.set(datetime.now().strftime("%Y-%m-%d"))
        self.status_var = tk.StringVar()
        self.status_var.set(self.status_options[0])  # Default to Open
        self.affected_systems_var = tk.StringVar()
        
        # Create widgets
        self.create_widgets()
        
        # Load incident data
        self.load_incidents()

    def validate_date_selection(self, event=None):
        """Validate the selected date"""
        try:
            selected_date = self.date_picker.get_date()
            current_date = datetime.now().date()
            
            # Check if date is in the future
            if selected_date > current_date:
                messagebox.showwarning("Invalid Date", 
                                    "Cannot select a future date for security incidents.\n"
                                    "Please select today's date or an earlier date.")
                # Reset to current date
                self.date_picker.set_date(current_date)
                return False
            
            # Check if date is too far in the past (optional - adjust as needed)
            days_diff = (current_date - selected_date).days
            if days_diff > 365:  # More than 1 year ago
                if not messagebox.askyesno("Old Date Warning", 
                                        f"The selected date is {days_diff} days ago.\n"
                                        "Are you sure this is correct?"):
                    self.date_picker.set_date(current_date)
                    return False
            
            return True
            
        except Exception as e:
            messagebox.showerror("Date Error", f"Invalid date selection: {str(e)}")
            self.date_picker.set_date(datetime.now().date())
            return False

    def init_database(self):
        """Initialize SQLite database and create tables if they don't exist"""
        if not os.path.exists('data'):
            os.makedirs('data')
            
        conn = sqlite3.connect('data/security_incidents.db')
        cursor = conn.cursor()
        
        # Create incidents table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT,
            category TEXT,
            description TEXT,
            date TEXT,
            status TEXT,
            affected_systems TEXT
        )
        ''')
        
        conn.commit()
        return conn

    def create_widgets(self):
        """Create all GUI widgets"""
        # Configure style for dark theme
        style = ttk.Style()
        style.theme_use('default')
        
        # Configure colors
        bg_color = "#1e1e1e"
        fg_color = "#ffffff"
        highlight_color = "#3700B3"
        accent_color = "#03DAC6"
        warning_color = "#CF6679"
        
        # Configure ttk styles
        style.configure("Treeview", 
                        background=bg_color, 
                        foreground=fg_color, 
                        fieldbackground=bg_color)
        style.map('Treeview', background=[('selected', highlight_color)])
        
        # Main frame
        main_frame = tk.Frame(self.root, bg=bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame for input form and incident list
        left_frame = tk.Frame(main_frame, bg=bg_color)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create form frame
        form_frame = tk.LabelFrame(left_frame, text="Log New Security Incident", bg=bg_color, fg=fg_color, font=("Arial", 12, "bold"))
        form_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Severity
        severity_frame = tk.Frame(form_frame, bg=bg_color)
        severity_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(severity_frame, text="Severity:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        severity_dropdown = ttk.Combobox(severity_frame, textvariable=self.severity_var, values=self.severity_levels, font=("Arial", 10), width=15)
        severity_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Category
        category_frame = tk.Frame(form_frame, bg=bg_color)
        category_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(category_frame, text="Category:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        category_dropdown = ttk.Combobox(category_frame, textvariable=self.category_var, values=self.categories, font=("Arial", 10), width=15)
        category_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Description
        desc_frame = tk.Frame(form_frame, bg=bg_color)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(desc_frame, text="Description:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Entry(desc_frame, textvariable=self.description_var, font=("Arial", 10), width=30, bg="#2d2d2d", fg=fg_color).pack(side=tk.LEFT, padx=5)
        
        # Affected Systems
        systems_frame = tk.Frame(form_frame, bg=bg_color)
        systems_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(systems_frame, text="Affected Systems:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Entry(systems_frame, textvariable=self.affected_systems_var, font=("Arial", 10), width=30, bg="#2d2d2d", fg=fg_color).pack(side=tk.LEFT, padx=5)
        
        # Date
        date_frame = tk.Frame(form_frame, bg=bg_color)
        date_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(date_frame, text="Date:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

        self.date_picker = DateEntry(date_frame, 
                           width=12, 
                           background='darkblue',
                           foreground='white', 
                           borderwidth=2,
                           font=("Arial", 10),
                           date_pattern='yyyy-mm-dd',
                           state='readonly')
        self.date_picker.pack(side=tk.LEFT, padx=5)

        # Bind validation event
        self.date_picker.bind("<<DateEntrySelected>>", self.validate_date_selection)

        # Status
        status_frame = tk.Frame(form_frame, bg=bg_color)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(status_frame, text="Status:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        status_dropdown = ttk.Combobox(status_frame, textvariable=self.status_var, values=self.status_options, font=("Arial", 10), width=15)
        status_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = tk.Frame(form_frame, bg=bg_color)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        tk.Button(button_frame, text="Log Incident", command=self.add_incident, bg=accent_color, fg="#000000", font=("Arial", 10, "bold"), padx=10).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Clear Form", command=self.clear_form, bg=warning_color, fg="#000000", font=("Arial", 10, "bold"), padx=10).pack(side=tk.LEFT, padx=5)
        
        # Incident list frame
        list_frame = tk.LabelFrame(left_frame, text="Security Incidents", bg=bg_color, fg=fg_color, font=("Arial", 12, "bold"))
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for incident list
        self.tree = ttk.Treeview(list_frame, columns=("ID", "Severity", "Category", "Description", "Status", "Date"), show="headings", selectmode="browse")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Description", text="Description")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Date", text="Date")
        
        self.tree.column("ID", width=30)
        self.tree.column("Severity", width=70)
        self.tree.column("Category", width=100)
        self.tree.column("Description", width=200)
        self.tree.column("Status", width=80)
        self.tree.column("Date", width=100)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar to treeview
        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind treeview selection event
        self.tree.bind("<ButtonRelease-1>", self.select_incident)
        
        # Create control buttons
        control_frame = tk.Frame(list_frame, bg=bg_color)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(control_frame, text="Delete Incident", command=self.delete_incident, bg=warning_color, fg="#000000", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Edit Incident", command=self.edit_incident, bg=highlight_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="View Details", command=self.view_incident_details, bg=highlight_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        # Right frame for statistics and charts
        right_frame = tk.Frame(main_frame, bg=bg_color)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Statistics frame
        stats_frame = tk.LabelFrame(right_frame, text="Security Statistics", bg=bg_color, fg=fg_color, font=("Arial", 12, "bold"))
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Labels for statistics
        self.total_label = tk.Label(stats_frame, text="Total Incidents: 0", bg=bg_color, fg=fg_color, font=("Arial", 10))
        self.total_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.open_label = tk.Label(stats_frame, text="Open Incidents: 0", bg=bg_color, fg=fg_color, font=("Arial", 10))
        self.open_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.critical_label = tk.Label(stats_frame, text="Critical Incidents: 0", bg=bg_color, fg=fg_color, font=("Arial", 10))
        self.critical_label.pack(anchor=tk.W, padx=5, pady=2)
        
        self.monthly_label = tk.Label(stats_frame, text="This Month: 0", bg=bg_color, fg=fg_color, font=("Arial", 10))
        self.monthly_label.pack(anchor=tk.W, padx=5, pady=2)
        
        # Chart frame
        self.chart_frame = tk.LabelFrame(right_frame, text="Security Analysis", bg=bg_color, fg=fg_color, font=("Arial", 12, "bold"))
        self.chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Chart type selection
        chart_selection_frame = tk.Frame(self.chart_frame, bg=bg_color)
        chart_selection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(chart_selection_frame, text="Chart Type:", bg=bg_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        self.chart_type = tk.StringVar()
        self.chart_type.set("Category")
        
        chart_types = ["Category", "Severity", "Monthly", "Status"]
        chart_dropdown = ttk.Combobox(chart_selection_frame, textvariable=self.chart_type, values=chart_types, font=("Arial", 10), width=10)
        chart_dropdown.pack(side=tk.LEFT, padx=5)
        
        tk.Button(chart_selection_frame, text="Generate Chart", command=self.generate_chart, bg=highlight_color, fg=fg_color, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        # Placeholder for chart
        self.chart_placeholder = tk.Frame(self.chart_frame, bg=bg_color)
        self.chart_placeholder.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Export/Import frame
        export_frame = tk.Frame(right_frame, bg=bg_color)
        export_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(export_frame, text="Export Data", command=self.export_data, bg="#FF9800", fg="#000000", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(export_frame, text="Generate Report", command=self.generate_report, bg="#4CAF50", fg="#000000", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(export_frame, text="Reset Database", command=self.reset_database, bg="#9E9E9E", fg="#000000", font=("Arial", 10)).pack(side=tk.RIGHT, padx=5)

    def load_incidents(self):
        """Load incidents from database into treeview"""
        # Clear treeview
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Get incidents from database
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, severity, category, description, status, date FROM incidents ORDER BY date DESC")
        incidents = cursor.fetchall()
        
        # Insert incidents into treeview with color coding based on severity
        for incident in incidents:
            severity = incident[1]
            
            # Set tag based on severity for color coding
            if severity == "Critical":
                tag = "critical"
                self.tree.tag_configure("critical", background="#cf6679")
            elif severity == "High":
                tag = "high"
                self.tree.tag_configure("high", background="#ff9e00")
            elif severity == "Medium":
                tag = "medium"
                self.tree.tag_configure("medium", background="#ffde03")
            elif severity == "Low":
                tag = "low"
                self.tree.tag_configure("low", background="#b5ead7")
            else:
                tag = "info"
                self.tree.tag_configure("info", background="#1e1e1e")
            
            self.tree.insert("", "end", values=incident, tags=(tag,))
        
        # Update statistics
        self.update_statistics()

    def add_incident(self):
        """Add a new security incident to the database"""
        try:
            # Get form values
            severity = self.severity_var.get()
            category = self.category_var.get()
            description = self.description_var.get()
            date = self.date_picker.get()  # Get date from picker
            status = self.status_var.get()
            affected_systems = self.affected_systems_var.get()
            
            # Validate date
            if not self.validate_date_selection():
                return
            
            # Insert into database
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO incidents (severity, category, description, date, status, affected_systems) VALUES (?, ?, ?, ?, ?, ?)",
                (severity, category, description, date, status, affected_systems)
            )
            self.conn.commit()
            
            # Clear form and reload incidents
            self.clear_form()
            self.load_incidents()
            
            messagebox.showinfo("Success", "Security incident logged successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def clear_form(self):
        """Clear the input form"""
        self.severity_var.set(self.severity_levels[2])  # Default to Medium
        self.category_var.set(self.categories[0])
        self.description_var.set("")
        self.date_var.set(datetime.now().strftime("%Y-%m-%d"))
        self.status_var.set(self.status_options[0])  # Default to Open
        self.affected_systems_var.set("")

    def select_incident(self, event):
        """Handle incident selection from treeview"""
        # Get selected item
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        # Get values
        values = self.tree.item(selected_item)["values"]
        if not values:
            return
        
        # Get full incident details including affected systems
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (values[0],))
        incident = cursor.fetchone()
        
        if not incident:
            return
        
        # Set form values
        self.severity_var.set(incident[1])
        self.category_var.set(incident[2])
        self.description_var.set(incident[3])
        
        # Parse and set date
        try:
            incident_date = datetime.strptime(incident[4], "%Y-%m-%d").date()
            self.date_picker.set_date(incident_date)
        except ValueError:
            self.date_picker.set_date(datetime.now().date())
        
        self.status_var.set(incident[5])
        self.affected_systems_var.set(incident[6])

    def delete_incident(self):
        """Delete the selected incident"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an incident to delete.")
            return
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this security incident?"):
            return
        
        # Get incident ID
        incident_id = self.tree.item(selected_item)["values"][0]
        
        # Delete from database
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        self.conn.commit()
        
        # Reload incidents
        self.load_incidents()
        
        messagebox.showinfo("Success", "Security incident deleted successfully!")

    def edit_incident(self):
        """Edit the selected incident"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an incident to edit.")
            return
        
        try:
            # Get form values
            severity = self.severity_var.get()
            category = self.category_var.get()
            description = self.description_var.get()
            date = self.date_picker.get()  # Get date from picker
            status = self.status_var.get()
            affected_systems = self.affected_systems_var.get()
            
            # Validate date
            if not self.validate_date_selection():
                return
            
            # Get incident ID
            incident_id = self.tree.item(selected_item)["values"][0]
            
            # Update database
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE incidents SET severity = ?, category = ?, description = ?, date = ?, status = ?, affected_systems = ? WHERE id = ?",
                (severity, category, description, date, status, affected_systems, incident_id)
            )
            self.conn.commit()
            
            # Reload incidents
            self.load_incidents()
            
            messagebox.showinfo("Success", "Security incident updated successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def view_incident_details(self):
        """Show detailed view of the selected incident"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an incident to view.")
            return
        
        # Get incident ID
        incident_id = self.tree.item(selected_item)["values"][0]
        
        # Get incident details
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        incident = cursor.fetchone()
        
        if not incident:
            return
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Incident #{incident[0]} Details")
        details_window.geometry("500x400")
        details_window.configure(bg="#fefefe")
        
        # Add details to window
        details_frame = tk.Frame(details_window, bg="#f8f4f4")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_label = tk.Label(details_frame, 
                                text=f"Security Incident #{incident[0]}", 
                                font=("Arial", 14, "bold"), 
                                bg="#fffefe", 
                                fg="#ffffff")
        header_label.pack(pady=10)
        
        # Severity with color indicator
        severity_frame = tk.Frame(details_frame, bg="#f6f6f6")
        severity_frame.pack(fill=tk.X, pady=5)
        
        severity = incident[1]
        severity_color = "#cf6679" if severity == "Critical" else "#ff9e00" if severity == "High" else "#ffde03" if severity == "Medium" else "#b5ead7"
        
        severity_indicator = tk.Frame(severity_frame, width=20, height=20, bg=severity_color)
        severity_indicator.pack(side=tk.LEFT, padx=5)
        
        tk.Label(severity_frame, text=f"Severity: {severity}", font=("Arial", 12), bg="#ffffff", fg="#ffffff").pack(side=tk.LEFT, padx=5)
        
        # Other details
        details_text = tk.Text(details_frame, height=15, width=50, bg="#2d2d2d", fg="#ffffff", font=("Arial", 10))
        details_text.pack(pady=10, fill=tk.BOTH, expand=True)
        details_text.insert(tk.END, f"Category: {incident[2]}\n\n")
        details_text.insert(tk.END, f"Date: {incident[4]}\n\n")
        details_text.insert(tk.END, f"Status: {incident[5]}\n\n")
        details_text.insert(tk.END, f"Affected Systems: {incident[6]}\n\n")
        details_text.insert(tk.END, f"Description:\n{incident[3]}\n\n")
        details_text.config(state=tk.DISABLED)

    def update_statistics(self):
        """Update statistics labels"""
        cursor = self.conn.cursor()
        
        # Total incidents
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total = cursor.fetchone()[0] or 0
        self.total_label.config(text=f"Total Incidents: {total}")
        
        # Open incidents
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('Open', 'Investigating')")
        open_count = cursor.fetchone()[0] or 0
        self.open_label.config(text=f"Open Incidents: {open_count}")
        
        # Critical incidents
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'")
        critical = cursor.fetchone()[0] or 0
        self.critical_label.config(text=f"Critical Incidents: {critical}")
        
        # This month incidents
        current_month = datetime.now().strftime("%Y-%m")
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE date LIKE ?", (f"{current_month}%",))
        monthly = cursor.fetchone()[0] or 0
        self.monthly_label.config(text=f"This Month: {monthly}")

    def generate_chart(self):
        """Generate chart based on selected chart type"""
        # Clear previous chart
        for widget in self.chart_placeholder.winfo_children():
            widget.destroy()
        
        # Configure matplotlib for dark theme
        plt.style.use('dark_background')
        
        chart_type = self.chart_type.get()
        cursor = self.conn.cursor()
        
        if chart_type == "Category":
            # Category distribution chart
            cursor.execute("SELECT category, COUNT(*) FROM incidents GROUP BY category")
            data = cursor.fetchall()
            
            if not data:
                messagebox.showinfo("No Data", "No incident data to display")
                return
            
            categories = [row[0] for row in data]
            counts = [row[1] for row in data]
            
            # Create pie chart
            fig, ax = plt.subplots(figsize=(4, 3))
            ax.pie(counts, labels=categories, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')
            plt.title('Incidents by Category')
            
        elif chart_type == "Severity":
            # Severity distribution chart
            cursor.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
            data = cursor.fetchall()
            
            if not data:
                messagebox.showinfo("No Data", "No incident data to display")
                return
            
            # Sort by severity level
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
            data = sorted(data, key=lambda x: severity_order.get(x[0], 999))
            
            severities = [row[0] for row in data]
            counts = [row[1] for row in data]
            
            # Create bar chart with color coding
            fig, ax = plt.subplots(figsize=(4, 3))
            colors = ['#cf6679', '#ff9e00', '#ffde03', '#b5ead7', '#c8d5b9']
            bars = ax.bar(severities, counts, color=colors[:len(severities)])
            plt.title('Incidents by Severity')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
        elif chart_type == "Monthly":
            # Monthly incidents chart
            cursor.execute("SELECT strftime('%Y-%m', date) as month, COUNT(*) FROM incidents GROUP BY month ORDER BY month")
            data = cursor.fetchall()
            
            if not data:
                messagebox.showinfo("No Data", "No incident data to display")
                return
            
            months = [row[0] for row in data]
            counts = [row[1] for row in data]
            
            # Create line chart
            fig, ax = plt.subplots(figsize=(4, 3))
            ax.plot(months, counts, marker='o', color='#03DAC6')
            plt.title('Monthly Incident Trends')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
        elif chart_type == "Status":
            # Status distribution chart
            cursor.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status")
            data = cursor.fetchall()
            
            if not data:
                messagebox.showinfo("No Data", "No incident data to display")
                return
            
            # Sort by workflow stage
            status_order = {"Open": 0, "Investigating": 1, "Contained": 2, "Resolved": 3, "Closed": 4}
            data = sorted(data, key=lambda x: status_order.get(x[0], 999))
            
            statuses = [row[0] for row in data]
            counts = [row[1] for row in data]
            
            # Create horizontal bar chart
            fig, ax = plt.subplots(figsize=(4, 3))
            ax.barh(statuses, counts, color='#3700B3')
            plt.title('Incidents by Status')
            plt.tight_layout()
        
        # Embed chart in tkinter window
        canvas = FigureCanvasTkAgg(fig, master=self.chart_placeholder)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def export_data(self):
        """Export incident data to CSV file"""
        try:
            # Get data from database
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM incidents")
            data = cursor.fetchall()
            
            if not data:
                messagebox.showinfo("No Data", "No incident data to export")
                return
            
            # Create dataframe
            df = pd.DataFrame(data, columns=["ID", "Severity", "Category", "Description", "Date", "Status", "Affected Systems"])
            
            # Export to CSV
            if not os.path.exists('exports'):
                os.makedirs('exports')
                
            export_file = f"exports/security_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(export_file, index=False)
            
            messagebox.showinfo("Export Successful", f"Data exported to {export_file}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred during export: {str(e)}")

    def generate_report(self):
        """Generate a comprehensive security report"""
        try:
            # Get data from database
            cursor = self.conn.cursor()
            
            # Get all incidents
            cursor.execute("SELECT * FROM incidents ORDER BY date DESC")
            incidents = cursor.fetchall()
            
            if not incidents:
                messagebox.showinfo("No Data", "No incident data for report generation")
                return
            
            # Get statistics
            cursor.execute("SELECT COUNT(*) FROM incidents")
            total = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('Open', 'Investigating')")
            open_count = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'")
            critical = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'High'")
            high = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity IN ('Critical', 'High') AND status IN ('Open', 'Investigating')")
            high_risk = cursor.fetchone()[0] or 0
            
            # Get category breakdown
            cursor.execute("SELECT category, COUNT(*) FROM incidents GROUP BY category ORDER BY COUNT(*) DESC")
            categories = cursor.fetchall()
            
            # Create report
            if not os.path.exists('reports'):
                os.makedirs('reports')
                
            report_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(report_file, 'w') as f:
                f.write("============================================\n")
                f.write("           SECURITY INCIDENT REPORT         \n")
                f.write("============================================\n\n")
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("EXECUTIVE SUMMARY\n")
                f.write("----------------\n")
                f.write(f"Total Incidents: {total}\n")
                f.write(f"Open Incidents: {open_count}\n")
                f.write(f"Critical Incidents: {critical}\n")
                f.write(f"High Incidents: {high}\n")
                f.write(f"High Risk (Critical/High and Open): {high_risk}\n\n")
                
                f.write("RISK ASSESSMENT\n")
                f.write("--------------\n")
                risk_level = "HIGH" if high_risk >= 3 else "MEDIUM" if high_risk >= 1 else "LOW"
                f.write(f"Current Security Risk Level: {risk_level}\n\n")
                
                f.write("INCIDENT BREAKDOWN BY CATEGORY\n")
                f.write("-----------------------------\n")
                for category in categories:
                    f.write(f"{category[0]}: {category[1]}\n")
                f.write("\n")
                
                f.write("CRITICAL INCIDENTS\n")
                f.write("-----------------\n")
                cursor.execute("SELECT * FROM incidents WHERE severity = 'Critical' ORDER BY date DESC")
                critical_incidents = cursor.fetchall()
                
                if critical_incidents:
                    for incident in critical_incidents:
                        f.write(f"ID: {incident[0]}\n")
                        f.write(f"Category: {incident[2]}\n")
                        f.write(f"Date: {incident[4]}\n")
                        f.write(f"Status: {incident[5]}\n")
                        f.write(f"Affected Systems: {incident[6]}\n")
                        f.write(f"Description: {incident[3]}\n")
                        f.write("---\n")
                else:
                    f.write("No critical incidents recorded.\n")
                f.write("\n")
                
                f.write("RECENT INCIDENTS (LAST 5)\n")
                f.write("------------------------\n")
                cursor.execute("SELECT * FROM incidents ORDER BY date DESC LIMIT 5")
                recent = cursor.fetchall()
                
                for incident in recent:
                    f.write(f"ID: {incident[0]} | {incident[1]} | {incident[2]} | {incident[5]}\n")
                    f.write(f"Date: {incident[4]}\n")
                    f.write(f"Affected: {incident[6]}\n")
                    f.write(f"Description: {incident[3]}\n")
                    f.write("---\n")
                f.write("\n")
                
                f.write("RECOMMENDATIONS\n")
                f.write("--------------\n")
                if high_risk >= 3:
                    f.write("URGENT: High number of critical/high severity open incidents.\n")
                    f.write("Immediate attention and resources required for incident response.\n")
                elif high_risk >= 1:
                    f.write("IMPORTANT: Critical/high severity incidents require attention.\n")
                    f.write("Allocate resources to address these incidents promptly.\n")
                else:
                    f.write("NORMAL: Continue monitoring and addressing incidents according to standard procedures.\n")
                f.write("\n")
                
                f.write("============================================\n")
                f.write("               END OF REPORT                \n")
                f.write("============================================\n")
            
            messagebox.showinfo("Report Generated", f"Security report saved to {report_file}")
            
        except Exception as e:
            messagebox.showerror("Report Error", f"An error occurred during report generation: {str(e)}")

    def reset_database(self):
        """Reset the database (clear all incidents)"""
        if not messagebox.askyesno("Confirm Reset", "Are you sure you want to delete ALL security incidents? This cannot be undone."):
            return
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM incidents")
            self.conn.commit()
            
            self.load_incidents()
            messagebox.showinfo("Reset Successful", "All security incidents have been deleted.")
            
        except Exception as e:
            messagebox.showerror("Reset Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityIncidentTracker(root)
    root.mainloop()
