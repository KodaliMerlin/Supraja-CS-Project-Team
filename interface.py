import tkinter as tk
from tkinter import Listbox, Scrollbar, Canvas
import math

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")

# Set window size
root.geometry("1000x1000")  # Adjusted size to fit all elements

# Set window background color
root.configure(bg='#1e1e1e')

# Add a canvas to enable scrolling
canvas = Canvas(root, bg='#1e1e1e')
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrollbar to the canvas
scrollbar = Scrollbar(root, orient=tk.VERTICAL, command=canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

canvas.config(yscrollcommand=scrollbar.set)
canvas.bind('<Configure>', lambda e: canvas.config(scrollregion=canvas.bbox("all")))

# Create a frame inside the canvas
frame = tk.Frame(canvas, bg='#1e1e1e')
canvas.create_window((0, 0), window=frame, anchor="nw")

# Add title label with a larger font size and adjusted padding
title_label = tk.Label(frame, text="Packet Sniffer", fg="#00ffff", bg="#1e1e1e", font=("Helvetica", 20, "bold"))
title_label.pack(pady=(20, 10))

# Add project info button with wrapping text
def show_project_info():
    tk.messagebox.showinfo("Project Info", "Network Packets Sniffer")

project_info_button = tk.Button(frame, text="Project Info", command=show_project_info, bg='#607d8b', fg='white', font=("Helvetica", 12), relief=tk.RAISED)
project_info_button.pack(pady=(0, 10))

# Function placeholders for button commands
def select_filter():
    pass

def view_logs():
    pass

def start_sniffing():
    pass

def captured_data():
    pass

def stop_sniffing():
    pass

def generate_password():
    pass

def send_email():
    pass

def analyze_logs():
    pass

def capture_http_headers():
    pass

def capture_db_username():
    pass

def analyze_website():
    pass

# Frame for filter selection with better padding
filter_frame = tk.Frame(frame, bg='#1e1e1e')
filter_frame.pack(pady=(0, 20), padx=20)  # Increased pady for better separation

filter_label = tk.Label(filter_frame, text="Select Filter", fg="#00ffff", bg='#1e1e1e', font=("Helvetica", 14, "bold"))
filter_label.pack(pady=(0, 10))

# Create filter selection listbox with scrollbar
filter_listbox = Listbox(filter_frame, selectmode=tk.MULTIPLE, bg='white', fg='black', font=("Helvetica", 12), height=5, width=15)  # Adjusted height to fit all items
filter_listbox.pack(side=tk.LEFT)

scrollbar = Scrollbar(filter_frame, orient=tk.VERTICAL, command=filter_listbox.yview)
scrollbar.pack(side=tk.LEFT, fill=tk.Y)

filter_listbox.config(yscrollcommand=scrollbar.set)

filters = ["All", "tcp port 80", "tcp port 443", "udp", "icmp"]
for filter in filters:
    filter_listbox.insert(tk.END, filter)

# Frame for oval buttons
oval_frame = tk.Frame(frame, bg='#1e1e1e', width=1000, height=600)  # Increased size
oval_frame.pack(pady=(20, 20))  # Adjusted to be below filter_frame

# Central button
stop_sniffing_button = tk.Button(oval_frame, text="Stop Sniffing", command=stop_sniffing, bg='#9c27b0', fg='white', font=("Helvetica", 12, "bold"), height=2, relief=tk.RAISED)
stop_sniffing_button.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

# Create buttons with consistent styling and padding
buttons = [
    ("Select Filter", '#007acc', select_filter),
    ("View Logs", '#4caf50', view_logs),
    ("Start Sniffing", '#f44336', start_sniffing),
    ("Captured Data", '#ffeb3b', captured_data),
    ("Generate Password", '#ff5722', generate_password),
    ("Send Email", '#03a9f4', send_email),
    ("Analyze Logs", '#8bc34a', analyze_logs),
    ("Capture HTTP Headers", '#ff9800', capture_http_headers),
    ("Capture DB Username", '#9e9e9e', capture_db_username),
    ("Analyze Website", '#607d8b', analyze_website)
]

# Arrange oval buttons
a = 300  # Semi-major axis
b = 200  # Semi-minor axis
angle_step = 360 / len(buttons)

for i, (text, color, command) in enumerate(buttons):
    angle = math.radians(i * angle_step)
    x = a * math.cos(angle) + oval_frame.winfo_reqwidth() / 2
    y = b * math.sin(angle) + oval_frame.winfo_reqheight() / 2
    button = tk.Button(oval_frame, text=text, command=command, bg=color, fg='black', font=("Helvetica", 10), height=2, width=18, relief=tk.RAISED)  # Adjusted width
    button.place(x=x, y=y, anchor=tk.CENTER)

# Center the frame within the canvas
def center_frame(event):
    canvas_width = event.width
    canvas_height = event.height
    frame_width = frame.winfo_reqwidth()
    frame_height = frame.winfo_reqheight()
    canvas.create_window((canvas_width / 2, canvas_height / 2), window=frame, anchor="center")

canvas.bind("<Configure>", center_frame)

# Update the scroll region when the frame size changes
def on_frame_configure(event):
    canvas.config(scrollregion=canvas.bbox("all"))

frame.bind("<Configure>", on_frame_configure)

# Run the main loop
root.mainloop()