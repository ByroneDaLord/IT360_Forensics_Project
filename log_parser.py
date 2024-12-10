import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import re
import os

try:
    import matplotlib.pyplot as plt
    import folium
except ImportError:
    messagebox.showerror("Error", "Please install required libraries: matplotlib, folium")


def analyze_log_file(log_file, time_window_minutes=5, threshold=10, ip_filter=None):
    """
    Analyze a log file for suspicious IP activity with optional IP filtering.
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
                    if ip_filter and ip != ip_filter:
                        continue  # Skip if the IP does not match the filter
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
    global results, log_file
    log_file = filedialog.askopenfilename(
        title="Select a Log File",
        initialdir=".",  # Start in the current directory
        filetypes=[("Log Files", "*.txt *.log"), ("All Files", "*.*")]
    )
    if not log_file:
        return

    reset_signals()
    start_progress()
    threading.Thread(target=process_log_file, args=(log_file,)).start()


def process_log_file(log_file):
    """
    Process the log file and display results after analysis.
    """
    global results
    try:
        time_window = int(time_entry.get())
        threshold = int(threshold_entry.get())
        ip_filter = ip_filter_entry.get().strip()
    except ValueError:
        messagebox.showerror("Error", "Please enter valid numeric values for time window and threshold.")
        stop_progress()
        return

    results = analyze_log_file(log_file, time_window_minutes=time_window, threshold=threshold, ip_filter=ip_filter)
    stop_progress()

    if results:
        display_results(results)
        show_distress_signal()
    else:
        show_positive_signal()


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


def sanitize_logs(log_file):
    """
    Create a sanitized version of the log file.
    """
    sanitized_file = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Sanitized Log"
    )
    if sanitized_file:
        with open(log_file, "r") as infile, open(sanitized_file, "w") as outfile:
            for line in infile:
                sanitized_line = re.sub(r"\d+\.\d+\.\d+\.\d+", "XXX.XXX.XXX.XXX", line)
                outfile.write(sanitized_line)
        messagebox.showinfo("Success", f"Sanitized log saved to {sanitized_file}")


def show_graph(results):
    """
    Display a bar chart of suspicious IPs.
    """
    if not results:
        messagebox.showinfo("Info", "No data to visualize!")
        return

    ips = list(results.keys())
    counts = [len(details) for details in results.values()]

    plt.figure(figsize=(10, 6))
    plt.bar(ips, counts, color='red')
    plt.title("Suspicious IPs")
    plt.xlabel("IP Addresses")
    plt.ylabel("Number of Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def show_map(results):
    """
    Generate a map of suspicious IP locations.
    """
    if not results:
        messagebox.showinfo("Info", "No data to map!")
        return

    world_map = folium.Map(location=[20, 0], zoom_start=2)

    for ip, details in results.items():
        for detail in details:
            country = detail[2]
            # Mock latitude/longitude lookup (replace with real GeoIP data)
            lat, lon = 20.0, 0.0
            folium.Marker(
                location=[lat, lon],
                popup=f"IP: {ip}\nCountry: {country}",
                icon=folium.Icon(color="red")
            ).add_to(world_map)

    world_map.save("suspicious_ips_map.html")
    os.system("suspicious_ips_map.html")


def show_positive_signal():
    """
    Show a positive signal indicating no malicious logs were found.
    """
    signal_label.config(text="✅ No Malicious Logs Found!", fg="green")


def show_distress_signal():
    """
    Show a distress signal indicating malicious logs were found.
    """
    signal_label.config(text="⚠️ Malicious Logs Detected!", fg="red")


def reset_signals():
    """
    Reset the signal label to default.
    """
    signal_label.config(text="")


def start_progress():
    """
    Start the progress bar.
    """
    progress.pack(pady=10)
    progress.start()


def stop_progress():
    """
    Stop the progress bar.
    """
    progress.stop()
    progress.pack_forget()


# GUI Configuration
root = tk.Tk()
root.title("Log Analyzer")
root.geometry("1400x900")
root.configure(bg="#1e272e")

header_frame = tk.Frame(root, bg="#3c6382", height=80)
header_frame.pack(fill=tk.X)
header_label = tk.Label(header_frame, text="Log Analyzer - Detect and Review Suspicious Activity", bg="#3c6382", fg="white", font=("Helvetica", 24, "bold"))
header_label.pack(pady=20)

main_frame = tk.Frame(root, bg="#1e272e", pady=20)
main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

inputs_frame = tk.Frame(main_frame, bg="#1e272e")
inputs_frame.pack(pady=10)

time_label = tk.Label(inputs_frame, text="Time Window (minutes):", bg="#1e272e", fg="white", font=("Helvetica", 14))
time_label.grid(row=0, column=0, padx=5, pady=5)
time_entry = tk.Entry(inputs_frame, font=("Helvetica", 14), width=5)
time_entry.grid(row=0, column=1, padx=5, pady=5)
time_entry.insert(0, "5")

threshold_label = tk.Label(inputs_frame, text="Threshold (failed attempts):", bg="#1e272e", fg="white", font=("Helvetica", 14))
threshold_label.grid(row=0, column=2, padx=5, pady=5)
threshold_entry = tk.Entry(inputs_frame, font=("Helvetica", 14), width=5)
threshold_entry.grid(row=0, column=3, padx=5, pady=5)
threshold_entry.insert(0, "10")

ip_filter_label = tk.Label(inputs_frame, text="IP Filter:", bg="#1e272e", fg="white", font=("Helvetica", 14))
ip_filter_label.grid(row=1, column=0, padx=5, pady=5)
ip_filter_entry = tk.Entry(inputs_frame, font=("Helvetica", 14), width=20)
ip_filter_entry.grid(row=1, column=1, padx=5, pady=5)

signal_label = tk.Label(main_frame, text="", bg="#1e272e", fg="white", font=("Helvetica", 16, "bold"))
signal_label.pack(pady=10)

loading_label = tk.Label(main_frame, text="", bg="#1e272e", fg="#f7b731", font=("Helvetica", 14, "italic"))
loading_label.pack(pady=5)

progress = ttk.Progressbar(main_frame, mode="indeterminate", length=300)

buttons_frame = tk.Frame(main_frame, bg="#1e272e")
buttons_frame.pack(pady=20)
load_button = tk.Button(buttons_frame, text="Load Log File", command=load_log_file, bg="#78e08f", fg="#1e272e", font=("Helvetica", 16, "bold"), relief=tk.RAISED, padx=15, pady=10)
load_button.grid(row=0, column=0, padx=10)
graph_button = tk.Button(buttons_frame, text="Show Graph", command=lambda: show_graph(results), bg="#8e44ad", fg="white", font=("Helvetica", 16, "bold"), relief=tk.RAISED, padx=15, pady=10)
graph_button.grid(row=0, column=1, padx=10)
map_button = tk.Button(buttons_frame, text="Show Map", command=lambda: show_map(results), bg="#27ae60", fg="white", font=("Helvetica", 16, "bold"), relief=tk.RAISED, padx=15, pady=10)
map_button.grid(row=0, column=2, padx=10)
sanitize_button = tk.Button(buttons_frame, text="Sanitize Logs", command=lambda: sanitize_logs(log_file), bg="#e67e22", fg="white", font=("Helvetica", 16, "bold"), relief=tk.RAISED, padx=15, pady=10)
sanitize_button.grid(row=0, column=3, padx=10)

results_frame = tk.Frame(main_frame, bg="#1e272e")
results_frame.pack(fill=tk.BOTH, expand=True)

uiarea1_frame = tk.Frame(results_frame, bg="#1e272e")
uiarea1_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15)
uiarea1_label = tk.Label(uiarea1_frame, text="Suspicious IPs", bg="#1e272e", fg="white", font=("Helvetica", 16, "bold"))
uiarea1_label.pack(anchor="w", pady=10)
uiarea1 = tk.Text(uiarea1_frame, height=25, width=50, bg="#34495e", fg="white", font=("Courier", 12), relief=tk.FLAT, wrap=tk.WORD)
uiarea1.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

uiarea2_frame = tk.Frame(results_frame, bg="#1e272e")
uiarea2_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=15)
uiarea2_label = tk.Label(uiarea2_frame, text="IP Details", bg="#1e272e", fg="white", font=("Helvetica", 16, "bold"))
uiarea2_label.pack(anchor="w", pady=10)
uiarea2 = tk.Text(uiarea2_frame, height=25, width=50, bg="#34495e", fg="white", font=("Courier", 12), relief=tk.FLAT, wrap=tk.WORD)
uiarea2.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

footer_frame = tk.Frame(root, bg="#3c6382", height=50)
footer_frame.pack(fill=tk.X)
footer_label = tk.Label(footer_frame, text="© 2024 Log Analyzer | Powered by Tkinter", bg="#3c6382", fg="white", font=("Helvetica", 12, "italic"))
footer_label.pack(pady=10)

root.mainloop()
