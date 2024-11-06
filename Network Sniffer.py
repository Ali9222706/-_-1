import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")
        self.is_fullscreen = False  # Track fullscreen state
        self.toggle_fullscreen()  # Start in fullscreen mode
        master.configure(bg="#f0f0f0")

        # Create a label for the title
        self.title_label = tk.Label(master, text="Live Packet Sniffer", font=("Helvetica", 20), bg="#f0f0f0")
        self.title_label.pack(pady=10)

        # Create a text area to display captured packets
        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, bg="#ffffff", font=("Courier New", 10))
        self.text_area.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

        # Create a frame for buttons
        self.button_frame = tk.Frame(master, bg="#f0f0f0")
        self.button_frame.pack(pady=5)

        # Create a start button
        self.start_button = tk.Button(self.button_frame, text="Start Capturing", command=self.start_capturing, bg="#4CAF50", fg="white", font=("Helvetica", 12))
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Create a stop button
        self.stop_button = tk.Button(self.button_frame, text="Stop Capturing", command=self.stop_capturing, bg="#f44336", fg="white", font=("Helvetica", 12))
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.sniffer_thread = None
        self.is_sniffing = False

        # Define lists for dangerous and safe IPs
        self.dangerous_ips = {"192.168.1.100", "10.0.0.5"}  # Add dangerous IPs here
        self.safe_ips = {"192.168.1.1", "10.0.0.1"}  # Add safe IPs here

        # Configure color tags for the text area
        self.text_area.tag_config("danger", foreground="red")
        self.text_area.tag_config("safe", foreground="blue")
        self.text_area.tag_config("neutral", foreground="black")

        # Bind key press event to toggle full screen
        self.master.bind("<F11>", self.toggle_fullscreen)  # F11 to toggle fullscreen
        self.master.bind("<Escape>", self.exit_fullscreen)  # Escape to exit fullscreen

    def toggle_fullscreen(self, event=None):
        self.is_fullscreen = not self.is_fullscreen
        self.master.attributes("-fullscreen", self.is_fullscreen)
        self.master.bind("<Configure>", self.on_resize)  # Optional: handle resizing

    def exit_fullscreen(self, event=None):
        self.is_fullscreen = False
        self.master.attributes("-fullscreen", False)

    def on_resize(self, event):
        self.text_area.config(width=event.width // 8, height=event.height // 30)  # Adjust text area size

    def start_capturing(self):
        self.is_sniffing = True
        self.text_area.delete(1.0, tk.END)  # Clear previous output
        self.text_area.insert(tk.END, "Starting packet capture...\n", ("neutral",))
        
        # Start the sniffer in a new thread
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_capturing(self):
        self.is_sniffing = False
        self.text_area.insert(tk.END, "Stopping packet capture...\n", ("neutral",))

    def sniff_packets(self):
        # This function runs in a separate thread
        # Capture packets indefinitely until stopped
        sniff(prn=self.packet_callback, store=0)

    def packet_callback(self, packet):
        # Check if capturing is still active
        if not self.is_sniffing:
            return
        
        # Extract packet details
        packet_info = self.extract_packet_info(packet)
        self.display_packet_info(packet_info, packet)

    def extract_packet_info(self, packet):
        """ Extract relevant information from the packet. """
        # Basic packet info
        info = f"Packet: {packet.summary()}\n"

        # Check for different layers and extract information
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
        """ Display packet information in the text area with color coding. """
        # Extract the IP information for color coding
        ip_layer = packet[IP] if IP in packet else None
        source_ip = ip_layer.src if ip_layer else "Unknown"
        dest_ip = ip_layer.dst if ip_layer else "Unknown"

        # Determine the color based on the IP
        if source_ip in self.dangerous_ips or dest_ip in self.dangerous_ips:
            color_tag = "danger"
        elif source_ip in self.safe_ips or dest_ip in self.safe_ips:
            color_tag = "safe"
        else:
            color_tag = "neutral"  # Default color for neutral IPs

        # Insert the packet information with the determined color
        self.text_area.insert(tk.END, packet_info + "\n", (color_tag,))
        self.text_area.see(tk.END)  # Scroll to the end

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
