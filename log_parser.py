import tkinter as tk
from tkinter import filedialog, messagebox
from collections import defaultdict
from datetime import datetime, timedelta
import re
import os
import threading


def analyze_log_file(log_file, time_window_minutes=5, threshold=10):
    """
    Analyze a log file for suspicious IP activity.
    """
    from collections import deque
    try:
        import geoip2.database
    except ImportError:
        messagebox.showerror("Error", "GeoIP2 module not found. Install it with 'pip install geoip2'")
        return {}

    LOG_PATTERN = re.compile(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)')
    GEOIP_DB_PATH = "C:/Users/YourUsername/Documents/GeoLite2-City.mmdb"  # Update this path
    failed_attempts = defaultdict(lambda: deque())
    suspicious_ips = defaultdict(list)
    time_window = timedelta(minutes=time_window_minutes)

    # Check if GeoLite2 database file exists
    if not os.path.exists(GEOIP_DB_PATH):
        messagebox.showerror("Error", f"GeoLite2 database not found at {GEOIP_DB_PATH}")
        return {}

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as geoip_reader, open(log_file, "r") as file:
            for line_number, line in enumerate(file, start=1):
                match = LOG_PATTERN.match(line)
                if match:
                    ip, timestamp, request, status, _ = match.groups()
                    if '/login' in request and int(status) == 401:
                        time = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
                        attempts = failed_attempts[ip]
                        attempts.append((line_number, time))
                        
                        while attempts and time - attempts[0][1] > time_window:
                            attempts.popleft()
                        
                        if len(attempts) >= threshold:
                            try:
                                country = geoip_reader.city(ip).country.name
                            except Exception:
                                country = "Unknown"
                            suspicious_ips[ip].append((line_number, time, country))
    except FileNotFoundError:
        messagebox.showerror("Error", "Log file not found!")
        return {}
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return {}
    return suspicious_ips


def load_log_file():
    """
    Load a log file using file dialog and analyze it.
    """
    log_file = filedialog.askopenfilename(
        title="Select a Log File",
        initialdir=".",  # Start in the current directory
        filetypes=[("Log Files", "*.txt *.log"), ("All Files", "*.*")]
    )
    if not log_file:
        return

    # Show loading indicator
    loading_label.config(text="Loading...")
    loading_label.update()

    # Use threading to avoid freezing the GUI
    threading.Thread(target=process_log_file, args=(log_file,)).start()


def process_log_file(log_file):
    """
    Process the log file and display results after analysis.
    """
    results = analyze_log_file(log_file)
    loading_label.config(text="")  # Hide loading indicator after completion

    if results:
        display_results(results)
    else:
        messagebox.showinfo("Results", "No suspicious activity detected.")


def display_results(results):
    """
    Display the analysis results in the text areas.
    """
    uiarea1.delete("1.0", tk.END)
    uiarea2.delete("1.0", tk.END)

    for ip, details in results.items():
        uiarea1.insert(tk.END, f"IP: {ip}\n")
        for detail in details:
            line, time, country = detail
            uiarea2.insert(tk.END, f"Line: {line}, Time: {time}, Country: {country}\n")
        uiarea1.insert(tk.END, "\n")


def clear_output():
    """
    Clear the output areas for a fresh analysis.
    """
    uiarea1.delete("1.0", tk.END)
    uiarea2.delete("1.0", tk.END)


# Set up the main application window
root = tk.Tk()
root.title("Log Analyzer")
root.geometry("1400x800")
root.configure(bg="#1e272e")  # Dark background

# Header
header_frame = tk.Frame(root, bg="#3c6382", height=80)
header_frame.pack(fill=tk.X)

header_label = tk.Label(
    header_frame,
    text="Log Analyzer - Detect and Review Suspicious Activity",
    bg="#3c6382",
    fg="white",
    font=("Helvetica", 24, "bold")
)
header_label.pack(pady=20)

# Main content frame
main_frame = tk.Frame(root, bg="#1e272e", pady=20)
main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

# Loading Indicator
loading_label = tk.Label(main_frame, text="", bg="#1e272e", fg="#f7b731", font=("Helvetica", 14, "italic"))
loading_label.pack(pady=5)

# Buttons frame
buttons_frame = tk.Frame(main_frame, bg="#1e272e")
buttons_frame.pack(pady=20)

load_button = tk.Button(
    buttons_frame,
    text="Load Log File",
    command=load_log_file,
    bg="#78e08f",
    fg="#1e272e",
    font=("Helvetica", 16, "bold"),
    relief=tk.RAISED,
    padx=15,
    pady=10,
)
load_button.grid(row=0, column=0, padx=10)

clear_button = tk.Button(
    buttons_frame,
    text="Clear Output",
    command=clear_output,
    bg="#e55039",
    fg="white",
    font=("Helvetica", 16, "bold"),
    relief=tk.RAISED,
    padx=15,
    pady=10,
)
clear_button.grid(row=0, column=1, padx=10)

# Results Areas
results_frame = tk.Frame(main_frame, bg="#1e272e")
results_frame.pack(fill=tk.BOTH, expand=True)

# Suspicious IPs
uiarea1_frame = tk.Frame(results_frame, bg="#1e272e")
uiarea1_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15)

uiarea1_label = tk.Label(
    uiarea1_frame,
    text="Suspicious IPs",
    bg="#1e272e",
    fg="white",
    font=("Helvetica", 16, "bold")
)
uiarea1_label.pack(anchor="w", pady=10)

uiarea1 = tk.Text(
    uiarea1_frame,
    height=25,
    width=50,
    bg="#34495e",
    fg="white",
    font=("Courier", 12),
    relief=tk.FLAT,
    wrap=tk.WORD
)
uiarea1.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# IP Details
uiarea2_frame = tk.Frame(results_frame, bg="#1e272e")
uiarea2_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=15)

uiarea2_label = tk.Label(
    uiarea2_frame,
    text="IP Details",
    bg="#1e272e",
    fg="white",
    font=("Helvetica", 16, "bold")
)
uiarea2_label.pack(anchor="w", pady=10)

uiarea2 = tk.Text(
    uiarea2_frame,
    height=25,
    width=50,
    bg="#34495e",
    fg="white",
    font=("Courier", 12),
    relief=tk.FLAT,
    wrap=tk.WORD
)
uiarea2.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Footer
footer_frame = tk.Frame(root, bg="#3c6382", height=50)
footer_frame.pack(fill=tk.X)

footer_label = tk.Label(
    footer_frame,
    text="© 2024 Log Analyzer | Powered by Tkinter",
    bg="#3c6382",
    fg="white",
    font=("Helvetica", 12, "italic")
)
footer_label.pack(pady=10)

# Run the Tkinter main loop
root.mainloop()
