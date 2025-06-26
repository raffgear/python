import threading
import time
import socket
import struct
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import customtkinter as ctk
from tkinter import scrolledtext, StringVar, BooleanVar, messagebox
import platform
from scapy.arch.windows import get_windows_if_list
from scapy.arch import get_if_list

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class DHCPLease:
    def __init__(self, mac, ip, hostname, lease_time):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.lease_start = time.time()
        self.lease_time = lease_time
        self.active = True

    def is_expired(self):
        return (time.time() - self.lease_start) > self.lease_time

class DHCPServer:
    def __init__(self, config_callback, log_callback):
        self.running = False
        self.config_callback = config_callback
        self.log_callback = log_callback
        self.leases = {}
        self.lease_pool = set()
        self.server_ip = ""
        self.interface = ""

    def start(self):
        config = self.config_callback()
        self.interface = config['interface']
        self.server_ip = config['server_ip']
        
        # Initialize IP pool
        self.lease_pool = self.generate_ip_pool(
            config['start_ip'], 
            config['end_ip']
        )
        
        self.running = True
        self.log("Server started")
        threading.Thread(target=self.sniff_dhcp, daemon=True).start()

    def stop(self):
        self.running = False
        self.log("Server stopped")

    def generate_ip_pool(self, start_ip, end_ip):
        start = struct.unpack("!I", socket.inet_aton(start_ip))[0]
        end = struct.unpack("!I", socket.inet_aton(end_ip))[0]
        return {socket.inet_ntoa(struct.pack("!I", i)) for i in range(start, end + 1)}

    def get_available_ip(self, mac):
        # Check for existing lease
        if mac in self.leases:
            lease = self.leases[mac]
            if not lease.is_expired():
                return lease.ip
            else:
                self.lease_pool.add(lease.ip)
                del self.leases[mac]
        
        # Get new IP
        if self.lease_pool:
            ip = self.lease_pool.pop()
            return ip
        return None

    def create_option_43(self, phone_ip):
        # Unify Option 43 format: [0x01, 0x04] + IP bytes
        ip_bytes = socket.inet_aton(phone_ip)
        return bytes([43, 6, 1, 4]) + ip_bytes

    def handle_dhcp(self, packet):
        if not packet.haslayer(DHCP):
            return
        
        config = self.config_callback()
        mac = packet[Ether].src
        hostname = ""
        
        # Extract hostname from DHCP options
        dhcp_options = packet[DHCP].options
        for option in dhcp_options:
            if option[0] == 'hostname':
                hostname = option[1].decode()
        
        # Process DHCP message types
        message_type = next((opt[1] for opt in dhcp_options if opt[0] == 'message-type'), None)
        
        if message_type == 1:  # DHCP Discover
            self.log(f"Discover from {mac} ({hostname})")
            offer_ip = self.get_available_ip(mac)
            
            if offer_ip:
                # Create DHCP Offer
                dhcp_options = [
                    ('message-type', 'offer'),
                    ('server_id', self.server_ip),
                    ('subnet_mask', config['subnet_mask']),
                    ('router', config['gateway']),
                    ('lease_time', config['lease_time']),
                    ('domain', config['domain']),
                    ('name_server', config['dns'])
                ]
                
                # Add Unify Option 43 if requested
                if config['enable_unify']:
                    dhcp_options.append(('param_req_list', [43]))
                    dhcp_options.append(('vendor_specific', self.create_option_43(config['phone_ip'])))
                
                dhcp_offer = Ether(dst=mac)/IP(src=self.server_ip, dst=offer_ip)
                dhcp_offer /= UDP(sport=67, dport=68)
                dhcp_offer /= BOOTP(
                    op=2,
                    yiaddr=offer_ip,
                    siaddr=self.server_ip,
                    chaddr=packet[Ether].src,
                    xid=packet[BOOTP].xid
                )
                dhcp_offer /= DHCP(options=dhcp_options)
                
                sendp(dhcp_offer, iface=self.interface, verbose=0)
                self.log(f"Offered {offer_ip} to {mac}")

        elif message_type == 3:  # DHCP Request
            self.log(f"Request from {mac} ({hostname})")
            requested_ip = next((opt[1] for opt in dhcp_options if opt[0] == 'requested_addr'), None)
            
            if requested_ip and requested_ip in self.lease_pool:
                self.lease_pool.remove(requested_ip)
                self.leases[mac] = DHCPLease(
                    mac, requested_ip, hostname, config['lease_time']
                )
                
                # Create DHCP Ack
                dhcp_options = [
                    ('message-type', 'ack'),
                    ('server_id', self.server_ip),
                    ('subnet_mask', config['subnet_mask']),
                    ('router', config['gateway']),
                    ('lease_time', config['lease_time']),
                    ('domain', config['domain']),
                    ('name_server', config['dns'])
                ]
                
                # Add Unify Option 43 if enabled
                if config['enable_unify']:
                    dhcp_options.append(('param_req_list', [43]))
                    dhcp_options.append(('vendor_specific', self.create_option_43(config['phone_ip'])))
                
                dhcp_ack = Ether(dst=mac)/IP(src=self.server_ip, dst=requested_ip)
                dhcp_ack /= UDP(sport=67, dport=68)
                dhcp_ack /= BOOTP(
                    op=2,
                    yiaddr=requested_ip,
                    siaddr=self.server_ip,
                    chaddr=packet[Ether].src,
                    xid=packet[BOOTP].xid
                )
                dhcp_ack /= DHCP(options=dhcp_options)
                
                sendp(dhcp_ack, iface=self.interface, verbose=0)
                self.log(f"ACK sent for {requested_ip} to {mac}")

    def sniff_dhcp(self):
        sniff_filter = "udp and (port 67 or port 68)"
        while self.running:
            try:
                sniff(prn=self.handle_dhcp, stop_filter=lambda _: not self.running,
                      filter=sniff_filter, iface=self.interface, count=1)
            except Exception as e:
                self.log(f"Error: {str(e)}")
                time.sleep(1)

    def log(self, message):
        self.log_callback(message)

def get_network_interfaces():
    """Get available network interfaces with filtering"""
    if platform.system() == "Windows":
        # Get all interfaces
        interfaces = get_windows_if_list()
        
        # Filter criteria
        virtual_keywords = [
            'virtual', 'vmware', 'virtualbox', 'vpn', 'pseudo', 
            'loopback', 'teredo', 'microsoft', 'ppp', 'veth', 'docker',
            'wsl', 'hyper-v', 'bluetooth', 'pda', 'ndis', 'npcap'
        ]
        
        # Filter interfaces
        filtered = []
        for iface in interfaces:
            name = iface.get('name', '').lower()
            desc = iface.get('description', '').lower()
            guid = iface.get('guid', '').lower()
            ip = iface.get('ips', [])
            
            # Skip interfaces without IP
            if not ip:
                continue
                
            # Skip loopback interfaces
            if any(ip.startswith('127.') for ip in iface['ips'] if isinstance(ip, str)):
                continue
                
            # Skip virtual interfaces
            skip = False
            for keyword in virtual_keywords:
                if (keyword in name or 
                    keyword in desc or 
                    keyword in guid):
                    skip = True
                    break
                    
            if not skip:
                filtered.append(iface['name'])
        
        return filtered
    else:
        # For Linux/macOS
        interfaces = get_if_list()
        # Filter out virtual interfaces
        virtual_keywords = ['lo', 'docker', 'veth', 'virbr', 'vmnet', 'vboxnet', 'tun', 'tap']
        return [iface for iface in interfaces 
                if not any(keyword in iface for keyword in virtual_keywords)]

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Unify DHCP Server")
        self.geometry("1100x750")
        self.dhcp_server = DHCPServer(self.get_config, self.log_message)
        self.available_interfaces = get_network_interfaces()
        self.create_widgets()

    def create_widgets(self):
        # Control Buttons - TOP RIGHT
        self.control_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.control_frame.pack(fill="x", padx=20, pady=10, anchor="ne")
        self.control_frame.place(relx=1.0, rely=0.02, anchor="ne", x=-20, y=0)
        
        self.start_btn = ctk.CTkButton(
            self.control_frame, text="▶ Start Server", 
            command=self.start_server, fg_color="green", 
            width=140, height=40, font=ctk.CTkFont(size=14, weight="bold")
        )
        self.start_btn.pack(side="right", padx=(10, 0))
        
        self.stop_btn = ctk.CTkButton(
            self.control_frame, text="■ Stop Server", 
            command=self.stop_server, fg_color="#d9534f", 
            state="disabled", width=140, height=40, 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.stop_btn.pack(side="right", padx=(10, 0))
        
        # Main frame for configuration
        self.config_frame = ctk.CTkFrame(self)
        self.config_frame.pack(fill="x", padx=20, pady=(50, 10))
        
        # Server Configuration Section
        self.create_server_config()
        
        # Unify Configuration Section
        self.create_unify_config()
        
        # Active Leases Section
        self.leases_frame = ctk.CTkFrame(self)
        self.leases_frame.pack(fill="both", expand=True, padx=20, pady=10)
        self.create_leases_display()
        
        # Log Section
        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.pack(fill="x", padx=20, pady=10)
        
        self.log_label = ctk.CTkLabel(self.log_frame, text="Server Log")
        self.log_label.pack(pady=(0, 5), padx=5, anchor="w")
        
        self.log_area = scrolledtext.ScrolledText(
            self.log_frame, height=8, state="disabled"
        )
        self.log_area.pack(fill="x", padx=5, pady=(0, 5))
        
        # Refresh button at bottom
        self.refresh_btn = ctk.CTkButton(
            self, text="Refresh Leases", 
            command=self.update_leases_display, width=120
        )
        self.refresh_btn.pack(pady=(0, 10), anchor="e", padx=20)

    def create_server_config(self):
        # Section Label
        section_label = ctk.CTkLabel(
            self.config_frame, text="Server Configuration", 
            font=ctk.CTkFont(weight="bold"))
        section_label.grid(row=0, column=0, columnspan=4, pady=(0, 10), sticky="w")
        
        # Network Interface
        ctk.CTkLabel(self.config_frame, text="Network Interface:").grid(
            row=1, column=0, padx=5, pady=5, sticky="w")
        
        # Use dropdown for interface selection
        if self.available_interfaces:
            default_iface = self.available_interfaces[0]
        else:
            default_iface = "No interfaces found"
            self.available_interfaces = [default_iface]
        
        self.interface = ctk.CTkComboBox(
            self.config_frame, 
            values=self.available_interfaces,
            width=250
        )
        self.interface.set(default_iface)
        self.interface.grid(row=1, column=1, padx=5, pady=5)
        
        # Server IP
        ctk.CTkLabel(self.config_frame, text="Server IP:").grid(
            row=1, column=2, padx=5, pady=5, sticky="w")
        self.server_ip = ctk.CTkEntry(self.config_frame, width=150)
        self.server_ip.grid(row=1, column=3, padx=5, pady=5)
        self.server_ip.insert(0, "192.168.1.1")
        
        # IP Range
        ctk.CTkLabel(self.config_frame, text="IP Range:").grid(
            row=2, column=0, padx=5, pady=5, sticky="w")
        self.ip_frame = ctk.CTkFrame(self.config_frame, fg_color="transparent")
        self.ip_frame.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        self.start_ip = ctk.CTkEntry(self.ip_frame, width=100)
        self.start_ip.pack(side="left", padx=(0, 5))
        self.start_ip.insert(0, "192.168.1.100")
        
        ctk.CTkLabel(self.ip_frame, text="to").pack(side="left", padx=5)
        
        self.end_ip = ctk.CTkEntry(self.ip_frame, width=100)
        self.end_ip.pack(side="left", padx=(5, 0))
        self.end_ip.insert(0, "192.168.1.200")
        
        # Subnet Mask
        ctk.CTkLabel(self.config_frame, text="Subnet Mask:").grid(
            row=2, column=2, padx=5, pady=5, sticky="w")
        self.subnet_mask = ctk.CTkEntry(self.config_frame, width=150)
        self.subnet_mask.grid(row=2, column=3, padx=5, pady=5)
        self.subnet_mask.insert(0, "255.255.255.0")
        
        # Gateway
        ctk.CTkLabel(self.config_frame, text="Gateway:").grid(
            row=3, column=0, padx=5, pady=5, sticky="w")
        self.gateway = ctk.CTkEntry(self.config_frame, width=150)
        self.gateway.grid(row=3, column=1, padx=5, pady=5)
        self.gateway.insert(0, "192.168.1.1")
        
        # DNS Server
        ctk.CTkLabel(self.config_frame, text="DNS Server:").grid(
            row=3, column=2, padx=5, pady=5, sticky="w")
        self.dns = ctk.CTkEntry(self.config_frame, width=150)
        self.dns.grid(row=3, column=3, padx=5, pady=5)
        self.dns.insert(0, "8.8.8.8")
        
        # Domain Name
        ctk.CTkLabel(self.config_frame, text="Domain:").grid(
            row=4, column=0, padx=5, pady=5, sticky="w")
        self.domain = ctk.CTkEntry(self.config_frame, width=150)
        self.domain.grid(row=4, column=1, padx=5, pady=5)
        self.domain.insert(0, "local")
        
        # Lease Time
        ctk.CTkLabel(self.config_frame, text="Lease Time (s):").grid(
            row=4, column=2, padx=5, pady=5, sticky="w")
        self.lease_time = ctk.CTkEntry(self.config_frame, width=150)
        self.lease_time.grid(row=4, column=3, padx=5, pady=5)
        self.lease_time.insert(0, "86400")

    def create_unify_config(self):
        # Section Label
        section_label = ctk.CTkLabel(
            self.config_frame, text="Unify Configuration", 
            font=ctk.CTkFont(weight="bold"))
        section_label.grid(row=5, column=0, columnspan=4, pady=(15, 5), sticky="w")
        
        # Enable Unify Option
        self.enable_unify = BooleanVar(value=True)
        self.unify_check = ctk.CTkCheckBox(
            self.config_frame, text="Enable Unify Option 43",
            variable=self.enable_unify
        )
        self.unify_check.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        
        # Phone Server IP
        ctk.CTkLabel(self.config_frame, text="Phone Server IP:").grid(
            row=6, column=2, padx=5, pady=5, sticky="w")
        self.phone_ip = ctk.CTkEntry(self.config_frame, width=150)
        self.phone_ip.grid(row=6, column=3, padx=5, pady=5)
        self.phone_ip.insert(0, "192.168.1.10")
        
        # Information
        info_label = ctk.CTkLabel(
            self.config_frame, 
            text="Provides VoIP server address to Unify devices via DHCP Option 43",
            text_color="gray70"
        )
        info_label.grid(row=7, column=0, columnspan=4, padx=5, pady=5, sticky="w")

    def create_leases_display(self):
        # Section Label
        section_label = ctk.CTkLabel(
            self.leases_frame, text="Active Leases", 
            font=ctk.CTkFont(weight="bold"))
        section_label.pack(pady=(0, 10), padx=5, anchor="w")
        
        # Leases Table
        self.leases_table = ctk.CTkTextbox(
            self.leases_frame, state="disabled", height=200
        )
        self.leases_table.pack(fill="both", expand=True, padx=5, pady=5)

    def get_config(self):
        return {
            'interface': self.interface.get(),
            'server_ip': self.server_ip.get(),
            'start_ip': self.start_ip.get(),
            'end_ip': self.end_ip.get(),
            'subnet_mask': self.subnet_mask.get(),
            'gateway': self.gateway.get(),
            'dns': self.dns.get(),
            'domain': self.domain.get(),
            'lease_time': int(self.lease_time.get()),
            'enable_unify': self.enable_unify.get(),
            'phone_ip': self.phone_ip.get()
        }

    def start_server(self):
        try:
            if not self.interface.get() or self.interface.get() == "No interfaces found":
                messagebox.showerror("Error", "Please select a valid network interface")
                return
                
            self.dhcp_server.start()
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.log_message("Server started successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")

    def stop_server(self):
        self.dhcp_server.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_area.configure(state="normal")
        self.log_area.insert("end", log_entry)
        self.log_area.configure(state="disabled")
        self.log_area.see("end")
        
        # Update leases display when relevant events happen
        if "ACK" in message or "Request" in message:
            self.update_leases_display()

    def update_leases_display(self):
        leases = self.dhcp_server.leases
        table_header = "MAC Address\t\tIP Address\t\tHostname\t\tLease Expires\n"
        table_header += "-" * 80 + "\n"
        
        lease_text = table_header
        
        for mac, lease in leases.items():
            if lease.active and not lease.is_expired():
                expires = time.strftime(
                    "%Y-%m-%d %H:%M", 
                    time.localtime(lease.lease_start + lease.lease_time)
                )
                lease_text += f"{mac}\t{lease.ip}\t{lease.hostname}\t\t{expires}\n"
        
        self.leases_table.configure(state="normal")
        self.leases_table.delete("1.0", "end")
        self.leases_table.insert("1.0", lease_text)
        self.leases_table.configure(state="disabled")

    def on_closing(self):
        if self.dhcp_server.running:
            self.dhcp_server.stop()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()