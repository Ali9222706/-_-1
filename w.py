import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
from PIL import Image, ImageTk  # For adding icons to the UI

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Enhanced Packet Sniffer")
        self.is_sniffing = False
        self.is_paused = False
        master.geometry("800x600")

        # Styling and Icons
        self.start_icon = ImageTk.PhotoImage(Image.open("start.png").resize((24, 24), Image.ANTIALIAS))
        self.stop_icon = ImageTk.PhotoImage(Image.open("stop.png").resize((24, 24), Image.ANTIALIAS))
        self.clear_icon = ImageTk.PhotoImage(Image.open("clear.png").resize((24, 24), Image.ANTIALIAS))
        self.pause_icon = ImageTk.PhotoImage(Image.open("pause.png").resize((24, 24), Image.ANTIALIAS))

        # Title Label
        title_label = tk.Label(master, text="Enhanced Packet Sniffer", font=("Helvetica", 18, "bold"), fg="#333")
        title_label.pack(pady=10)

        # Main Frame with Buttons, Filters, and Text Area
        main_frame = tk.Frame(master, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Control Buttons and Protocol Filter
        control_frame = tk.Frame(main_frame, bg="#f0f0f0")
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        # Start/Stop/Pause/Clear Buttons
        self.start_button = tk.Button(control_frame, text="Start", image=self.start_icon, compound="left", command=self.start_capturing, font=("Helvetica", 12), bg="#4CAF50", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(control_frame, text="Stop", image=self.stop_icon, compound="left", command=self.stop_capturing, font=("Helvetica", 12), bg="#f44336", fg="white")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.pause_button = tk.Button(control_frame, text="Pause", image=self.pause_icon, compound="left", command=self.toggle_pause, font=("Helvetica", 12), bg="#FFA500", fg="white")
        self.pause_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = tk.Button(control_frame, text="Clear", image=self.clear_icon, compound="left", command=self.clear_text_area, font=("Helvetica", 12), bg="#008CBA", fg="white")
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Protocol Filter
        self.protocol_var = tk.StringVar(value="All")
        tk.Label(control_frame, text="Filter by Protocol:", bg="#f0f0f0").pack(side=tk.LEFT, padx=5)
        self.protocol_menu = ttk.Combobox(control_frame, textvariable=self.protocol_var, values=["All", "TCP", "UDP", "ICMP"], state="readonly", width=10)
        self.protocol_menu.pack(side=tk.LEFT)

        # Text Area for Packet Display
        self.text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Courier New", 10), bg="#ffffff", fg="#333")
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Status Bar
        self.status_bar = tk.Label(master, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure color tags for different IP categories
        self.text_area.tag_config("danger", foreground="red")
        self.text_area.tag_config("safe", foreground="blue")
        self.text_area.tag_config("neutral", foreground="black")

        # Initialize packet capture thread
        self.sniffer_thread = None

    def start_capturing(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.status_bar.config(text="Status: Capturing packets...")
            self.text_area.delete(1.0, tk.END)
            self.sniffer_thread = threading.Thread(target=self.sniff_packets)
            self.sniffer_thread.start()
        else:
            messagebox.showwarning("Warning", "Packet capturing is already running!")

    def stop_capturing(self):
        self.is_sniffing = False
        self.status_bar.config(text="Status: Stopped capturing packets.")
        if self.sniffer_thread:
            self.sniffer_thread.join()

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_button.config(text="Resume")
            self.status_bar.config(text="Status: Paused")
        else:
            self.pause_button.config(text="Pause")
            self.status_bar.config(text="Status: Capturing packets...")

    def clear_text_area(self):
        self.text_area.delete(1.0, tk.END)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0)

    def packet_callback(self, packet):
        if not self.is_sniffing or self.is_paused:
            return

        # Filter packets by selected protocol
        protocol = self.protocol_var.get()
        if protocol == "TCP" and not packet.haslayer(TCP):
            return
        elif protocol == "UDP" and not packet.haslayer(UDP):
            return
        elif protocol == "ICMP" and not packet.haslayer(ICMP):
            return

        # Extract packet details
        packet_info = self.extract_packet_info(packet)
        self.display_packet_info(packet_info, packet)

    def extract_packet_info(self, packet):
        """Extract and format relevant information from the packet."""
        info = f"Packet: {packet.summary()}\n"
        if IP in packet:
            ip_layer = packet[IP]
            info += f"Source: {ip_layer.src} -> Destination: {ip_layer.dst}\n"
        if TCP in packet:
            tcp_layer = packet[TCP]
            info += f"Protocol: TCP | Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}\n"
        elif UDP in packet:
            udp_layer = packet[UDP]
            info += f"Protocol: UDP | Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}\n"
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            info += f"Protocol: ICMP | Type: {icmp_layer.type} | Code: {icmp_layer.code}\n"
        return info

    def display_packet_info(self, packet_info, packet):
        ip_layer = packet[IP] if IP in packet else None
        source_ip = ip_layer.src if ip_layer else "Unknown"
        dest_ip = ip_layer.dst if ip_layer else "Unknown"
        
        color_tag = "neutral"
        if source_ip == "192.168.1.100" or dest_ip == "192.168.1.100":
            color_tag = "danger"
        elif source_ip == "192.168.1.1" or dest_ip == "192.168.1.1":
            color_tag = "safe"
        
        self.text_area.insert(tk.END, packet_info + "\n", (color_tag,))
        self.text_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
