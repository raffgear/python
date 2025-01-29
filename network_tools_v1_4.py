import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import wmi
import subprocess
import ctypes
import sys
import re
import json
import os
import requests
import threading
import signal

# Globale Variablen für den Ping-Tab
command_history = []  # Befehlsverlauf
history_index = -1  # Index für den Befehlsverlauf
current_process = None  # Aktueller Ping-Prozess
current_process2 = None  # Aktueller Tracert-Prozess


def is_admin():
    """Überprüft, ob das Programm mit Administratorrechten ausgeführt wird."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def validate_ip(ip):
    """Überprüft, ob die IP-Adresse gültig ist."""
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def validate_subnet(subnet):
    """Überprüft, ob die Subnetzmaske gültig ist."""
    return validate_ip(subnet)


def validate_gateway(gateway):
    """Überprüft, ob das Gateway gültig ist."""
    return validate_ip(gateway)


class NetworkToolsApp:
    def __init__(self, root):
        try:
            self.root = root
            self.root.title("Network Tools")

            # Schriftgröße und Stil
            self.font = ("Calibri", 12)
            self.font10 = ("Calibri", 10)
            self.font16 = ("Calibri", 16)
            self.font16bold = ("Calibri", 16,"bold")
            self.label_font = ("Calibri", 12, "bold")
            self.large_font = ("Calibri", 24, "bold")

            # Stil für ttk-Widgets
            self.style = ttk.Style()
            self.style.configure("TLabel", font=self.font16bold)
            self.style.configure("TButton", font=self.font)
            self.style.configure("TEntry", font=self.font)
            self.style.configure("TCombobox", font=self.font)

            # Überprüfen, ob das Programm mit Administratorrechten ausgeführt wird
            if not is_admin():
                print("keine Adminrechte")
                messagebox.showerror(
                    "Fehlende Berechtigungen",
                    "Das Programm muss mit Administratorrechten ausgeführt werden.",
                )
                sys.exit(1)

            # Notebook (Tabs) erstellen
            self.notebook = ttk.Notebook(root)
            self.notebook.pack(expand=True, fill="both")
            ##############################################################
            # Tab für Netzwerkkarten-Daten
            ##############################################################
            
            self.tab_network_interfaces = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_network_interfaces, text="Netzwerkkarten")

            # Dropdown für Netzwerkkarten-Auswahl
            self.label_select_interface = ttk.Label(
                self.tab_network_interfaces,
                text="Wählen Sie eine Netzwerkkarte:",
                style="TLabel",
            )
            self.label_select_interface.pack(pady=10)

            self.selected_interface = tk.StringVar()
            self.dropdown_interfaces = ttk.Combobox(
                self.tab_network_interfaces,
                textvariable=self.selected_interface,
                style="TCombobox",
                width=50,
            )
            self.dropdown_interfaces.pack(pady=10)
            self.dropdown_interfaces.bind(
                "<<ComboboxSelected>>", self.on_interface_select
            )

            # Optionsfeld für DHCP oder statische IP in einer Zeile
            self.frame_dhcp = ttk.Frame(self.tab_network_interfaces)
            self.frame_dhcp.pack(pady=10)

            self.label_dhcp = ttk.Label(
                self.frame_dhcp, text="IP-Konfiguration:", style="TLabel"
            )
            self.label_dhcp.pack(side=tk.LEFT, padx=5)

            self.dhcp_mode = tk.StringVar(value="DHCP")  # Standardmäßig DHCP
            self.radio_dhcp = ttk.Radiobutton(
                self.frame_dhcp,
                text="DHCP",
                variable=self.dhcp_mode,
                value="DHCP",
                command=self.toggle_dhcp_mode,
                style="TRadiobutton",
            )
            self.radio_dhcp.pack(side=tk.LEFT, padx=5)
            self.radio_static = ttk.Radiobutton(
                self.frame_dhcp,
                text="Statisch",
                variable=self.dhcp_mode,
                value="Statisch",
                command=self.toggle_dhcp_mode,
                style="TRadiobutton",
            )
            self.radio_static.pack(side=tk.LEFT, padx=5)

            # Felder für Netzwerkkarten-Daten
            self.frame_fields = ttk.Frame(self.tab_network_interfaces)
            self.frame_fields.pack(pady=10)

            # IP-Adresse
            self.label_ip = ttk.Label(
                self.frame_fields, text="IP-Adresse:", style="TLabel"
            )
            self.label_ip.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
            self.entry_ip = ttk.Entry(
                self.frame_fields, width=30, style="TEntry", state="readonly"
            )
            self.entry_ip.grid(row=0, column=1, padx=5, pady=5)

            # Subnetzmaske
            self.label_subnet = ttk.Label(
                self.frame_fields, text="Subnetzmaske:", style="TLabel"
            )
            self.label_subnet.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
            self.entry_subnet = ttk.Entry(
                self.frame_fields, width=30, style="TEntry", state="readonly"
            )
            self.entry_subnet.grid(row=1, column=1, padx=5, pady=5)

            # Gateway
            self.label_gateway = ttk.Label(
                self.frame_fields, text="Gateway:", style="TLabel"
            )
            self.label_gateway.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
            self.entry_gateway = ttk.Entry(
                self.frame_fields, width=30, style="TEntry", state="readonly"
            )
            self.entry_gateway.grid(row=2, column=1, padx=5, pady=5)

            # DNS-Server
            self.label_dns = ttk.Label(
                self.frame_fields, text="DNS-Server:", style="TLabel"
            )
            self.label_dns.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
            self.entry_dns = ttk.Entry(
                self.frame_fields, width=30, style="TEntry", state="readonly"
            )
            self.entry_dns.grid(row=3, column=1, padx=5, pady=5)

            # Button-Frame
            self.frame_buttons = ttk.Frame(self.tab_network_interfaces)
            self.frame_buttons.pack(pady=20)

            # Button zum Übernehmen der Einstellungen
            self.button_apply = ttk.Button(
                self.frame_buttons,
                text="Übernehmen",
                command=self.apply_settings,
                style="TButton",
            )
            self.button_apply.pack(side=tk.LEFT, padx=10)

            # Button zum Aktualisieren der Netzwerkkarten-Daten
            self.button_refresh = ttk.Button(
                self.frame_buttons,
                text="Aktualisieren",
                command=self.refresh_network_interfaces,
                style="TButton",
            )
            self.button_refresh.pack(side=tk.LEFT, padx=10)

            # Rahmen für Profile
            self.frame_profile = ttk.LabelFrame(
                self.tab_network_interfaces, text="Profile", padding=10
            )
            self.frame_profile.pack(pady=10, padx=10, fill="x")

            # Profilname Eingabefeld
            self.label_profile_name = ttk.Label(
                self.frame_profile, text="Profilname:", style="TLabel"
            )
            self.label_profile_name.pack(pady=5)

            self.entry_profile_name = ttk.Entry(
                self.frame_profile, width=30, style="TEntry"
            )
            self.entry_profile_name.pack(pady=5)
            self.entry_profile_name.bind("<KeyRelease>", self.toggle_save_button)

            # Button zum Speichern des Profils
            self.button_save_profile = ttk.Button(
                self.frame_profile,
                text="Profil speichern",
                command=self.save_profile,
                style="TButton",
                state=tk.DISABLED,  # Initial deaktiviert
            )
            self.button_save_profile.pack(pady=5)

            # Dropdown für Profilauswahl
            self.label_select_profile = ttk.Label(
                self.frame_profile, text="Wählen Sie ein Profil:", style="TLabel"
            )
            self.label_select_profile.pack(pady=5)

            self.selected_profile = tk.StringVar()
            self.dropdown_profiles = ttk.Combobox(
                self.frame_profile,
                textvariable=self.selected_profile,
                style="TCombobox",
                width=30,
            )
            self.dropdown_profiles.pack(pady=5)
            self.dropdown_profiles.bind("<<ComboboxSelected>>", self.on_profile_select)

            # Button zum Löschen des Profils
            self.button_delete_profile = ttk.Button(
                self.frame_profile,
                text="Profil löschen",
                command=self.delete_profile,
                style="TButton",
            )
            self.button_delete_profile.pack(pady=5)

            # Netzwerkkarten-Daten beim Start laden
            self.load_network_interfaces()

            # Profile beim Start laden
            self.load_profiles()

            ##############################################################
            # Neuer Tab für externe IP
            ##############################################################
            
            self.tab_external_ip = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_external_ip, text="Ext. IP")

            # Anzeigefeld für die externe IP
            self.label_external_ip = ttk.Label(
                self.tab_external_ip,
                text="Öffentliche IP-Adresse:",
                style="TLabel",
                font=self.font16bold,
            )
            self.label_external_ip.pack(pady=10)

            self.label_ip_display = ttk.Label(
                self.tab_external_ip,
                text="",
                style="TLabel",
                font=self.large_font,
                anchor="center",
            )
            self.label_ip_display.pack(pady=10, fill="x")
            self.label_ip_display.bind("<Double-1>", self.copy_ip_to_clipboard)

            self.label_ipv6_display = ttk.Label(
                self.tab_external_ip,
                text="",
                style="TLabel",
                font=self.font16,
                anchor="center",
            )
            self.label_ipv6_display.pack(pady=10, fill="x")
            self.label_ipv6_display.bind("<Double-1>", self.copy_ipv6_to_clipboard)

            # Button zum Abrufen der öffentlichen IP
            self.button_get_external_ip = ttk.Button(
                self.tab_external_ip,
                text="Öffentliche IP anzeigen",
                command=self.get_external_ip,
                style="TButton",
            )
            self.button_get_external_ip.pack(pady=10)

            ##############################################################
            # Neuer Tab für Ping
            ##############################################################
            
            self.tab_ping = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_ping, text="Ping")

            # Eingabefeld für die IP-Adresse oder Domain
            self.label_ping_ip = ttk.Label(
                self.tab_ping, text="IP-Adresse oder Domain:", style="TLabel"
            )
            self.label_ping_ip.pack(pady=10)

            # Frame für die entry und dropdownmenu
            self.frame_ping_frame = ttk.Frame(self.tab_ping)
            self.frame_ping_frame.pack(pady=10, padx=10)

            self.entry_ping_ip = ttk.Entry(
                self.frame_ping_frame, width=30, style="TEntry"
            )
            self.entry_ping_ip.pack(pady=10, side=tk.LEFT)
            self.entry_ping_ip.insert(0, "8.8.8.8")  # Vorbelegen mit 8.8.8.8
            self.entry_ping_ip.focus_set()
            self.entry_ping_ip.bind("<Return>", lambda e: self.start_ping())


            test_addresses = [
                # Deutsche Adressen und Domains
                "141.1.1.1",  # Deutsche Telekom DNS
                "217.237.151.97",  # Vodafone DNS
                "212.227.81.50",  # 1&1 DNS
                "185.48.116.101",  # Freenet DNS
                "194.25.0.60",  # Deutsche Telekom DNS
                "www.google.de",
                "www.amazon.de",
                "www.spiegel.de",
                "www.t-online.de",
                "www.gmx.net",
                # Englische Adressen und Domains
                "8.8.8.8",  # Google DNS
                "1.1.1.1",  # Cloudflare DNS
                "8.8.4.4",  # Google DNS
                "208.67.222.222",  # OpenDNS
                "208.67.220.220",  # OpenDNS
                "www.google.com",
                "www.facebook.com",
                "www.youtube.com",
                "www.twitter.com",
                "www.github.com",
            ]

    
            
            self.combobox_test_addresses_ping = ttk.Combobox(
                self.frame_ping_frame,  # oder self.tab_ping, je nach Bedarf
                values=test_addresses,
                state="readonly",
                width=30,
            )
            self.combobox_test_addresses_ping.pack(pady=10, padx=10, side=tk.RIGHT)
            self.combobox_test_addresses_ping.set(
                "Wählen Sie eine Adresse"
            )  # Standardtext

            # Event-Binding hinzufügen
            self.combobox_test_addresses_ping.bind(
                "<<ComboboxSelected>>", self.update_ip_entry_ping
            )

            # Frame für die Radiobuttons
            self.frame_ping_options = ttk.Frame(self.tab_ping)
            self.frame_ping_options.pack(pady=10)

            # Variable für die Radiobuttons
            self.ping_option = tk.StringVar(value="count")

            # Radiobutton für kontinuierliches Ping (-t)
            self.radio_ping_continuous = ttk.Radiobutton(
                self.frame_ping_options,
                text="-t (kontinuierlich)",
                variable=self.ping_option,
                value="continuous",
                style="TRadiobutton",
            )
            self.radio_ping_continuous.pack(side=tk.LEFT, padx=5)

            # Radiobutton für Anzahl der Ping-Pakete (-n)
            self.radio_ping_count = ttk.Radiobutton(
                self.frame_ping_options,
                text="Anzahl der Ping-Pakete:",
                variable=self.ping_option,
                value="count",
                style="TRadiobutton",
            )
            self.radio_ping_count.pack(side=tk.LEFT, padx=5)

            # Spinbox für die Anzahl der Ping-Pakete
            self.ping_count = tk.IntVar(value=4)  # Standardwert: 4
            self.spinbox_ping_count = ttk.Spinbox(
                self.frame_ping_options,
                from_=1,
                to=20,
                textvariable=self.ping_count,
                width=5,
                style="TSpinbox",
            )
            self.spinbox_ping_count.pack(side=tk.LEFT, padx=5)

            # Button-Frame für Ping
            self.frame_ping_buttons = ttk.Frame(self.tab_ping)
            self.frame_ping_buttons.pack(pady=10)

            # Button zum Starten des Ping
            self.button_ping_start = ttk.Button(
                self.frame_ping_buttons,
                text="Starten",
                command=self.start_ping,
                style="TButton",
            )
            self.button_ping_start.pack(side=tk.LEFT, padx=5)

            # Button zum Stoppen des Ping
            self.button_ping_stop = ttk.Button(
                self.frame_ping_buttons,
                text="Stoppen",
                command=self.stop_ping,
                style="TButton",
            )
            self.button_ping_stop.pack(side=tk.LEFT, padx=5)

            # Button zum Löschen der Ausgabe
            self.button_ping_clear = ttk.Button(
                self.frame_ping_buttons,
                text="Löschen",
                command=self.clear_ping_output,
                style="TButton",
            )
            self.button_ping_clear.pack(side=tk.LEFT, padx=5)

            # Textbox für die Ping-Ausgabe
            self.text_ping_output = scrolledtext.ScrolledText(
                self.tab_ping,
                width=30,  # Breite der Textbox (in Zeichen)
                height=15,  # Höhe der Textbox (in Zeilen)
                wrap=tk.WORD,
                font=self.font10,
            )
            self.text_ping_output.pack(pady=10, padx=10, fill="both", expand=True)

            ##############################################################
            # Neuer Tab für traceroute
            ##############################################################
            
            self.tab_traceroute = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_traceroute, text="Traceroute")

            # Eingabefeld für die IP-Adresse oder Domain
            self.label_tracert_ip = ttk.Label(
                self.tab_traceroute, text="IP-Adresse oder Domain:", style="TLabel"
            )
            self.label_tracert_ip.pack(padx=10, pady=10)
            # Neuer Frame für traceroute ip und dropdown
            self.frame_tracert_frame = ttk.Frame(self.tab_traceroute)
            self.frame_tracert_frame.pack(pady=10, padx=10)

            self.entry_tracert_ip = ttk.Entry(
                self.frame_tracert_frame, width=30, style="TEntry"
            )
            self.entry_tracert_ip.pack(pady=10, side=tk.LEFT)
            self.entry_tracert_ip.insert(0, "8.8.8.8")  # Vorbelegen mit 8.8.8.8
            self.entry_tracert_ip.focus_set()
            self.entry_tracert_ip.bind("<Return>", lambda e: self.start_tracert())

            # Tracert-Tab
            self.combobox_test_addresses_tracert = ttk.Combobox(
                self.frame_tracert_frame,  # oder self.tab_tracert, je nach Bedarf
                values=test_addresses,
                state="readonly",
                width=30,
            )
            self.combobox_test_addresses_tracert.pack(pady=10, padx=10, side=tk.RIGHT)
            self.combobox_test_addresses_tracert.set(
                "Wählen Sie eine Adresse"
            )  # Standardtext

            # Event-Binding hinzufügen
            self.combobox_test_addresses_tracert.bind(
                "<<ComboboxSelected>>", self.update_ip_entry_tracert
            )

            # Button-Frame für tracert
            self.frame_tracert_buttons = ttk.Frame(self.tab_traceroute)
            self.frame_tracert_buttons.pack(pady=10)

            # Button zum Starten des tracert
            self.button_tracert_start = ttk.Button(
                self.frame_tracert_buttons,
                text="Starten",
                command=self.start_tracert,
                style="TButton",
            )
            self.button_tracert_start.pack(side=tk.LEFT, padx=5)

            # Button zum Stoppen des tracert
            self.button_tracert_stop = ttk.Button(
                self.frame_tracert_buttons,
                text="Stoppen",
                command=self.stop_tracert,
                style="TButton",
            )
            self.button_tracert_stop.pack(side=tk.LEFT, padx=5)

            # Button zum Löschen der Ausgabe
            self.button_tracert_clear = ttk.Button(
                self.frame_tracert_buttons,
                text="Löschen",
                command=self.clear_tracert_output,
                style="TButton",
            )
            self.button_tracert_clear.pack(side=tk.LEFT, padx=5)

            # Textbox für die Ping-Ausgabe
            self.text_tracert_output = scrolledtext.ScrolledText(
                self.tab_traceroute,
                width=30,  # Breite der Textbox (in Zeichen)
                height=15,  # Höhe der Textbox (in Zeilen)
                wrap=tk.WORD,
                font=self.font10,
            )
            self.text_tracert_output.pack(pady=10, padx=10, fill="both", expand=True)

            # Ende tracert Tab
            
            
            ##############################################################
            # Neuer Tab für nslookup
            ##############################################################
            self.tab_nslookup = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_nslookup, text="NSLookup")

            # Label für die Domain-Eingabe
            self.label_domain = ttk.Label(self.tab_nslookup, text="Domain:")
            self.label_domain.pack(pady=5, padx=10, anchor='w')

            # Eingabefeld für die Domain
            self.entry_domain = ttk.Entry(self.tab_nslookup, width=50)
            self.entry_domain.pack(pady=5, padx=10, anchor='w')
            self.entry_domain.insert(0, "google.com")  # Vorbelegen mit google.com

            # Label für die Abfragetyp-Auswahl
            self.label_query_type = ttk.Label(self.tab_nslookup, text="Abfragetyp:")
            self.label_query_type.pack(pady=5, padx=10, anchor='w')

            # Combobox für die Abfragetyp-Auswahl
            self.combobox_query_type = ttk.Combobox(self.tab_nslookup, values=["ohne", "MX", "NS", "TEXT", "SOA"], state="readonly")
            self.combobox_query_type.pack(pady=5, padx=10, anchor='w')
            self.combobox_query_type.current(0)  # Standardmäßig den ersten Eintrag auswählen

            # Button zum Starten der Abfrage
            self.button_nslookup = ttk.Button(self.tab_nslookup, text="Abfrage starten", command=self.run_nslookup)
            self.button_nslookup.pack(pady=5, padx=10, anchor='w')

            # Textbox für die Ausgabe
            self.text_nslookup_output = scrolledtext.ScrolledText(self.tab_nslookup, width=80, height=20, wrap=tk.WORD)
            self.text_nslookup_output.pack(pady=10, padx=10, fill="both", expand=True)

            
            
            ##############################################################
            # Neuer Tab für nslookup ENDE
            ##############################################################          

            # Fenstergröße anpassen
            self.root.update_idletasks()
            # self.root.minsize(self.root.winfo_width(), self.root.winfo_height())
            self.root.geometry("420x700")

        except Exception as e:
            messagebox.showerror(
                "Kritischer Fehler", f"Das Programm konnte nicht gestartet werden: {e}"
            )
            sys.exit(1)

    def toggle_save_button(self, event):
        """Aktiviert oder deaktiviert den 'Profil speichern'-Button basierend auf dem Profilnamen."""
        if self.entry_profile_name.get().strip():
            self.button_save_profile.config(state=tk.NORMAL)
        else:
            self.button_save_profile.config(state=tk.DISABLED)

    def copy_ip_to_clipboard(self, event):
        """Kopiert die öffentliche IP-Adresse in die Zwischenablage."""
        ip_address = self.label_ip_display.cget("text")
        self.root.clipboard_clear()
        self.root.clipboard_append(ip_address)
        messagebox.showinfo(
            "Kopiert",
            f"IP-Adresse {ip_address} wurde in die Zwischenablage kopiert.",
        )

    def copy_ipv6_to_clipboard(self, event):
        """Kopiert die öffentliche IP-Adresse in die Zwischenablage."""
        ip_address = self.label_ipv6_display.cget("text")
        self.root.clipboard_clear()
        self.root.clipboard_append(ip_address)
        messagebox.showinfo(
            "Kopiert",
            f"IP-Adresse {ip_address} wurde in die Zwischenablage kopiert.",
        )

    def load_network_interfaces(self):
        """Lädt die verfügbaren Netzwerkkarten in das Dropdown-Menü."""
        try:
            self.interfaces = self.get_network_interfaces()
            if not self.interfaces:
                messagebox.showwarning(
                    "Keine Netzwerkkarten",
                    "Es wurden keine aktiven Netzwerkkarten gefunden.",
                )
                return

            self.dropdown_interfaces["values"] = list(self.interfaces.keys())

            # Zuletzt gewählte Netzwerkkarte laden
            last_selected_interface = self.load_last_selected_interface()
            if last_selected_interface in self.interfaces:
                self.selected_interface.set(last_selected_interface)
            else:
                self.selected_interface.set(list(self.interfaces.keys())[0])

            self.on_interface_select()
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Laden der Netzwerkkarten: {e}")

    def get_network_interfaces(self):
        """Ermittelt die verfügbaren Netzwerkkarten mit wmi."""
        try:
            c = wmi.WMI()
            interfaces = {}

            for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                interface_name = nic.Description
                ip_address = nic.IPAddress[0] if nic.IPAddress else ""
                subnet_mask = nic.IPSubnet[0] if nic.IPSubnet else ""
                gateway = nic.DefaultIPGateway[0] if nic.DefaultIPGateway else ""
                dns_servers = (
                    ", ".join(nic.DNSServerSearchOrder)
                    if nic.DNSServerSearchOrder
                    else ""
                )
                dhcp_enabled = nic.DHCPEnabled

                interfaces[interface_name] = {
                    "ip": ip_address,
                    "subnet": subnet_mask,
                    "gateway": gateway,
                    "dns": dns_servers,
                    "dhcp": dhcp_enabled,
                }

            return interfaces
        except Exception as e:
            print(f"Fehler beim Ermitteln der Netzwerkkarten: {e}")
            return {}

    def on_interface_select(self, event=None):
        """Wird aufgerufen, wenn eine Netzwerkkarte ausgewählt wird."""
        try:
            interface_name = self.selected_interface.get()
            if interface_name in self.interfaces:
                interface_data = self.interfaces[interface_name]

                # DHCP-Modus setzen
                if interface_data["dhcp"]:
                    self.dhcp_mode.set("DHCP")
                else:
                    self.dhcp_mode.set("Statisch")

                # Felder aktualisieren
                self.entry_ip.config(state="normal")
                self.entry_ip.delete(0, tk.END)
                self.entry_ip.insert(0, interface_data.get("ip", ""))
                self.entry_ip.config(state="readonly")

                self.entry_subnet.config(state="normal")
                self.entry_subnet.delete(0, tk.END)
                self.entry_subnet.insert(0, interface_data.get("subnet", ""))
                self.entry_subnet.config(state="readonly")

                self.entry_gateway.config(state="normal")
                self.entry_gateway.delete(0, tk.END)
                self.entry_gateway.insert(0, interface_data.get("gateway", ""))
                self.entry_gateway.config(state="readonly")

                self.entry_dns.config(state="normal")
                self.entry_dns.delete(0, tk.END)
                self.entry_dns.insert(0, interface_data.get("dns", ""))
                self.entry_dns.config(state="readonly")

                # DHCP-Modus umschalten
                self.toggle_dhcp_mode()

                # Zuletzt gewählte Netzwerkkarte speichern
                self.save_last_selected_interface(interface_name)
        except Exception as e:
            messagebox.showerror(
                "Fehler", f"Fehler beim Aktualisieren der Netzwerkkarten-Daten: {e}"
            )

    def toggle_dhcp_mode(self):
        """Aktiviert oder deaktiviert die Textfelder basierend auf dem DHCP-Modus."""
        if self.dhcp_mode.get() == "DHCP":
            self.entry_ip.config(state="readonly")
            self.entry_subnet.config(state="readonly")
            self.entry_gateway.config(state="readonly")
            self.entry_dns.config(state="readonly")
        else:
            self.entry_ip.config(state="normal")
            self.entry_subnet.config(state="normal")
            self.entry_gateway.config(state="normal")
            self.entry_dns.config(state="normal")

    def apply_settings(self):
        """Übernimmt die Einstellungen (DHCP oder statische IP)."""
        try:
            interface_name = self.selected_interface.get()
            if interface_name not in self.interfaces:
                messagebox.showwarning(
                    "Fehler", "Bitte wählen Sie eine Netzwerkkarte aus."
                )
                return

            if self.dhcp_mode.get() == "DHCP":
                # DHCP aktivieren
                self.set_dhcp(interface_name)
                messagebox.showinfo("Erfolg", "DHCP wurde erfolgreich aktiviert.")
            else:
                # Statische IP konfigurieren
                ip = self.entry_ip.get()
                subnet = self.entry_subnet.get()
                gateway = self.entry_gateway.get()
                dns = self.entry_dns.get().split(", ")

                # Validierung der statischen Daten
                if not validate_ip(ip):
                    messagebox.showwarning("Fehler", "Ungültige IP-Adresse.")
                    return
                if not validate_subnet(subnet):
                    messagebox.showwarning("Fehler", "Ungültige Subnetzmaske.")
                    return
                if gateway and not validate_gateway(gateway):
                    messagebox.showwarning("Fehler", "Ungültiges Gateway.")
                    return

                self.set_static_ip(interface_name, ip, subnet, gateway, dns)
                messagebox.showinfo(
                    "Erfolg", "Statische IP wurde erfolgreich konfiguriert."
                )

            # Netzwerkkarten-Daten neu laden
            self.load_network_interfaces()
            # Ausgewählte Netzwerkkarte erneut anzeigen
            self.selected_interface.set(interface_name)
            self.on_interface_select()
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def refresh_network_interfaces(self):
        """Aktualisiert die Netzwerkkarten-Daten."""
        try:
            self.load_network_interfaces()
            messagebox.showinfo(
                "Aktualisiert",
                "Die Netzwerkkarten-Daten wurden erfolgreich aktualisiert.",
            )
        except Exception as e:
            messagebox.showerror(
                "Fehler", f"Fehler beim Aktualisieren der Netzwerkkarten-Daten: {e}"
            )

    def set_dhcp(self, interface_name):
        """Aktiviert DHCP für die ausgewählte Netzwerkkarte."""
        try:
            c = wmi.WMI()
            nic = c.Win32_NetworkAdapterConfiguration(Description=interface_name)[0]
            # nic.SetGateways(DefaultIPGateway=[""])  # Leere Liste setzt Gateway zurück
            nic.EnableDHCP()
            # DNS-Server auch auf DHCP zurücksetzen
            nic.SetDNSServerSearchOrder()  # Leere Liste setzt DNS auf DHCP zurück
            # Gateway zurücksetzen
            print("Gateway zurücksetzen")

            nic.SetGateways(DefaultIPGateway=[""])  # Leere Liste setzt Gateway zurück
        except Exception as e:
            print(f"Fehler beim Aktivieren von DHCP: {e}")
            # Fallback: Verwende netsh
            subprocess.run(
                ["netsh", "interface", "ip", "set", "address", interface_name, "dhcp"],
                check=True,
            )
            # DNS-Server auf DHCP zurücksetzen
            subprocess.run(
                ["netsh", "interface", "ip", "set", "dns", interface_name, "dhcp"],
                check=True,
            )
            # Gateway zurücksetzen
            subprocess.run(
                [
                    "netsh",
                    "interface",
                    "ip",
                    "delete",
                    "address",
                    interface_name,
                    "gateway",
                ],
                check=True,
            )

    def set_static_ip(self, interface_name, ip, subnet, gateway, dns):
        """Setzt eine statische IP für die ausgewählte Netzwerkkarte."""
        try:
            c = wmi.WMI()
            nic = c.Win32_NetworkAdapterConfiguration(Description=interface_name)[0]
            nic.EnableStatic(IPAddress=[ip], SubnetMask=[subnet])
            if gateway:
                nic.SetGateways(DefaultIPGateway=[gateway])
            if dns:
                nic.SetDNSServerSearchOrder(dns)
        except Exception as e:
            print(f"Fehler beim Setzen der statischen IP: {e}")
            # Fallback: Verwende netsh
            subprocess.run(
                [
                    "netsh",
                    "interface",
                    "ip",
                    "set",
                    "address",
                    interface_name,
                    "static",
                    ip,
                    subnet,
                    gateway,
                ],
                check=True,
            )
            if dns:
                subprocess.run(
                    [
                        "netsh",
                        "interface",
                        "ip",
                        "set",
                        "dns",
                        interface_name,
                        "static",
                        dns[0],
                    ],
                    check=True,
                )

    def save_last_selected_interface(self, interface_name):
        """Speichert die zuletzt gewählte Netzwerkkarte in einer Datei."""
        try:
            with open("last_selected_interface.json", "w", encoding="utf-8") as file:
                json.dump({"last_selected_interface": interface_name}, file)
        except Exception as e:
            print(f"Fehler beim Speichern der zuletzt gewählten Netzwerkkarte: {e}")

    def load_last_selected_interface(self):
        """Lädt die zuletzt gewählte Netzwerkkarte aus einer Datei."""
        try:
            if os.path.exists("last_selected_interface.json"):
                with open(
                    "last_selected_interface.json", "r", encoding="utf-8"
                ) as file:
                    data = json.load(file)
                    return data.get("last_selected_interface", "")
            return ""
        except Exception as e:
            print(f"Fehler beim Laden der zuletzt gewählten Netzwerkkarte: {e}")
            return ""

    def save_profile(self):
        """Speichert die aktuellen IP-Daten unter einem Profilnamen."""
        try:
            profile_name = self.entry_profile_name.get()
            if not profile_name:
                messagebox.showwarning(
                    "Fehler", "Bitte geben Sie einen Profilnamen ein."
                )
                return

            interface_name = self.selected_interface.get()
            if interface_name not in self.interfaces:
                messagebox.showwarning(
                    "Fehler", "Bitte wählen Sie eine Netzwerkkarte aus."
                )
                return

            profile_data = {
                "interface_name": interface_name,
                "ip": self.entry_ip.get(),
                "subnet": self.entry_subnet.get(),
                "gateway": self.entry_gateway.get(),
                "dns": self.entry_dns.get(),
                "dhcp": self.dhcp_mode.get(),
            }

            profiles = self.load_profiles()
            profiles[profile_name] = profile_data

            with open("profiles.json", "w", encoding="utf-8") as file:
                json.dump(profiles, file)

            messagebox.showinfo("Erfolg", "Profil wurde erfolgreich gespeichert.")
            self.load_profiles()
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def load_profiles(self):
        """Lädt die gespeicherten Profile aus einer Datei."""
        try:
            if os.path.exists("profiles.json"):
                with open("profiles.json", "r", encoding="utf-8") as file:
                    profiles = json.load(file)
                    self.dropdown_profiles["values"] = list(profiles.keys())
                    return profiles
            return {}
        except Exception as e:
            print(f"Fehler beim Laden der Profile: {e}")
            return {}

    def on_profile_select(self, event=None):
        """Wird aufgerufen, wenn ein Profil ausgewählt wird."""
        try:
            profile_name = self.selected_profile.get()
            profiles = self.load_profiles()
            if profile_name in profiles:
                profile_data = profiles[profile_name]

                # Netzwerkkarte auswählen
                self.selected_interface.set(profile_data["interface_name"])
                self.on_interface_select()

                # IP-Daten setzen
                self.entry_ip.config(state="normal")
                self.entry_ip.delete(0, tk.END)
                self.entry_ip.insert(0, profile_data.get("ip", ""))
                self.entry_ip.config(state="readonly")

                self.entry_subnet.config(state="normal")
                self.entry_subnet.delete(0, tk.END)
                self.entry_subnet.insert(0, profile_data.get("subnet", ""))
                self.entry_subnet.config(state="readonly")

                self.entry_gateway.config(state="normal")
                self.entry_gateway.delete(0, tk.END)
                self.entry_gateway.insert(0, profile_data.get("gateway", ""))
                self.entry_gateway.config(state="readonly")

                self.entry_dns.config(state="normal")
                self.entry_dns.delete(0, tk.END)
                self.entry_dns.insert(0, profile_data.get("dns", ""))
                self.entry_dns.config(state="readonly")

                # DHCP-Modus setzen
                self.dhcp_mode.set(profile_data.get("dhcp", "DHCP"))
                self.toggle_dhcp_mode()
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Laden des Profils: {e}")

    def delete_profile(self):
        """Löscht das ausgewählte Profil."""
        try:
            profile_name = self.selected_profile.get()
            if not profile_name:
                messagebox.showwarning("Fehler", "Bitte wählen Sie ein Profil aus.")
                return

            profiles = self.load_profiles()
            if profile_name in profiles:
                del profiles[profile_name]
                with open("profiles.json", "w", encoding="utf-8") as file:
                    json.dump(profiles, file)
                messagebox.showinfo("Erfolg", "Profil wurde erfolgreich gelöscht.")
                self.load_profiles()
                self.selected_profile.set("")  # Dropdown zurücksetzen
            else:
                messagebox.showwarning(
                    "Fehler", "Das ausgewählte Profil existiert nicht."
                )
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def get_external_ip(self):
        """Ruft die öffentliche IP-Adresse ab und zeigt sie an."""
        try:
            response = requests.get("https://api.ipify.org/?format=json")
            if response.status_code == 200:
                ip_data = response.json()
                external_ip = ip_data.get("ip", "Unbekannt")
                self.label_ip_display.config(text=external_ip)
            else:
                messagebox.showerror(
                    "Fehler",
                    "Die öffentliche IP-Adresse konnte nicht abgerufen werden.",
                )
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")
        ##öffentliche ipv6
        try:
            response = requests.get("http://ipecho.net/plain")
            if response.status_code == 200:
                ip_data = response.text
                
                external_ipv6 = ip_data
                self.label_ipv6_display.config(text=external_ipv6)
            else:
                messagebox.showerror(
                    "Fehler",
                    "Die öffentliche IP-Adresse konnte nicht abgerufen werden.",
                )
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def execute_command(self):
        """Führt den eingegebenen Befehl aus und zeigt die Ausgabe in Echtzeit an."""
        # global history_index, current_process

        # Stoppe den aktuellen Prozess, falls vorhanden
        if current_process and current_process.poll() is None:
            current_process.terminate()
            current_process.wait()

        # Lösche die Ausgabe
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)

        cmd = self.command_entry.get()
        if cmd not in command_history:
            command_history.append(cmd)
            self.update_history_combobox()
        history_index = len(command_history)

        def run_command():
            global current_process
            current_process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            for line in current_process.stdout:
                decoded_line = line.decode("cp850")  # Dekodiere die Ausgabe mit cp850
                self.output_text.insert(tk.END, decoded_line)
                self.output_text.see(tk.END)  # Scrolle automatisch nach unten
                self.output_text.update_idletasks()

            current_process.stdout.close()
            current_process.wait()
            self.output_text.config(state=tk.DISABLED)

        threading.Thread(target=run_command).start()

    def stop_command(self):
        """Stoppt den aktuellen Ping-Prozess."""
        global current_process
        if current_process and current_process.poll() is None:
            current_process.terminate()
            current_process.wait()
            self.output_text.insert(tk.END, "\nProzess abgebrochen.\n")
            self.output_text.config(state=tk.DISABLED)

    def show_previous_command(self, event):
        """Zeigt den vorherigen Befehl aus dem Verlauf an."""
        global history_index
        if command_history and history_index > 0:
            history_index -= 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, command_history[history_index])

    def show_next_command(self, event):
        """Zeigt den nächsten Befehl aus dem Verlauf an."""
        global history_index
        if command_history and history_index < len(command_history) - 1:
            history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, command_history[history_index])

    def update_history_combobox(self):
        """Aktualisiert die Combobox mit dem Befehlsverlauf."""
        self.history_combobox["values"] = command_history

    def on_history_select(self, event):
        """Wird aufgerufen, wenn ein Befehl aus dem Verlauf ausgewählt wird."""
        selected_command = self.history_combobox.get()
        self.command_entry.delete(0, tk.END)
        self.command_entry.insert(0, selected_command)

    def update_ip_entry(self, event):
        """Aktualisiert das IP-Adressfeld mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses.get()
        self.entry_ping_ip.delete(0, tk.END)
        self.entry_ping_ip.insert(0, selected_address)

    def update_ip_entry_ping(self, event):
        """Aktualisiert das IP-Adressfeld im Ping-Tab mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses_ping.get()
        self.entry_ping_ip.delete(0, tk.END)
        self.entry_ping_ip.insert(0, selected_address)

    def update_ip_entry_tracert(self, event):
        """Aktualisiert das IP-Adressfeld im Tracert-Tab mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses_tracert.get()
        self.entry_tracert_ip.delete(0, tk.END)
        self.entry_tracert_ip.insert(0, selected_address)

    def start_ping(self):
        self.clear_ping_output()
        """Startet den Ping-Prozess basierend auf den ausgewählten Optionen."""
        global current_process

        # Überprüfen, ob ein Ping-Prozess bereits läuft
        if current_process and current_process.poll() is None:
            messagebox.showwarning("Fehler", "Ein Ping-Prozess läuft bereits.")
            return

        ip_or_domain = self.entry_ping_ip.get().strip()
        if not ip_or_domain:
            messagebox.showwarning(
                "Fehler", "Bitte geben Sie eine IP-Adresse oder Domain ein."
            )
            return

        cmd = ["ping"]
        if self.ping_option.get() == "continuous":
            cmd.append("-t")
        else:
            cmd.extend(["-n", str(self.ping_count.get())])
        cmd.append(ip_or_domain)

        def run_ping():
            global current_process
            try:
                # Starte den Ping-Prozess
                current_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    text=True,  # Textmodus für stdout/stderr
                    encoding="cp850",  # Kodierung für die Ausgabe
                )

                # Zeige die Ausgabe in Echtzeit an
                for line in current_process.stdout:
                    self.text_ping_output.config(state=tk.NORMAL)
                    self.text_ping_output.insert(tk.END, line)
                    self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                    self.text_ping_output.update_idletasks()
                    self.text_ping_output.config(state=tk.DISABLED)

                # Warte auf das Ende des Prozesses
                current_process.wait()
                self.text_ping_output.config(state=tk.NORMAL)
                self.text_ping_output.insert(tk.END, "\nPing-Prozess abgeschlossen.\n")
                self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                self.text_ping_output.update_idletasks()
                self.text_ping_output.config(state=tk.DISABLED)
                current_process = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
            except Exception as e:
                messagebox.showerror(
                    "Fehler", f"Fehler beim Starten des Ping-Prozesses: {e}"
                )
                current_process = (
                    None  # Setze den Prozess auf None, falls ein Fehler auftritt
                )

        # Starte den Ping-Prozess in einem separaten Thread
        threading.Thread(target=run_ping, daemon=True).start()

    def stop_ping(self):
        """Stoppt den laufenden Ping-Prozess."""
        global current_process
        if current_process and current_process.poll() is None:
            try:
                # Beende den Prozess zuverlässig
                current_process.terminate()  # Versuche, den Prozess zu beenden
                current_process.wait(
                    timeout=2
                )  # Warte bis zu 2 Sekunden auf das Beenden
                self.text_ping_output.config(state=tk.NORMAL)
                self.text_ping_output.insert(tk.END, "\nPing-Prozess wurde gestoppt.\n")
                self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                self.text_ping_output.update_idletasks()
                self.text_ping_output.config(state=tk.DISABLED)
                current_process = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
            except Exception as e:
                # Falls terminate() fehlschlägt, versuche kill()
                try:
                    current_process.kill()  # Erzwinge das Beenden des Prozesses
                    current_process.wait(
                        timeout=2
                    )  # Warte bis zu 2 Sekunden auf das Beenden
                    self.text_ping_output.config(state=tk.NORMAL)
                    self.text_ping_output.insert(
                        tk.END, "\nPing-Prozess wurde gestoppt.\n"
                    )
                    self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                    self.text_ping_output.update_idletasks()
                    self.text_ping_output.config(state=tk.DISABLED)
                    current_process = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
                except Exception as e:
                    messagebox.showerror(
                        "Fehler", f"Fehler beim Stoppen des Ping-Prozesses: {e}"
                    )
                    current_process = None

    def clear_ping_output(self):
        """Löscht die Ausgabe der Ping-Textbox."""
        self.text_ping_output.config(state=tk.NORMAL)
        self.text_ping_output.delete(1.0, tk.END)
        self.text_ping_output.config(state=tk.DISABLED)

    # -----------------tracert tab methods start-----------------
    def start_tracert(self):
        """Startet den Tracert-Prozess basierend auf den ausgewählten Optionen."""
        self.clear_tracert_output()
        global current_process2

        # Überprüfen, ob ein Tracert-Prozess bereits läuft
        if current_process2 and current_process2.poll() is None:
            messagebox.showwarning("Fehler", "Ein tracert-Prozess läuft bereits.")
            return

        ip_or_domain = self.entry_tracert_ip.get().strip()
        if not ip_or_domain:
            messagebox.showwarning(
                "Fehler", "Bitte geben Sie eine IP-Adresse oder Domain ein."
            )
            return

        self.cmd = ["tracert", ip_or_domain]
        threading.Thread(target=self.run_tracert).start()

    def run_tracert(self):
        global current_process2
        try:
            current_process2 = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="cp850",
            )

            for line in current_process2.stdout:
                self.text_tracert_output.config(state=tk.NORMAL)
                self.text_tracert_output.insert(tk.END, line)
                self.text_tracert_output.see(tk.END)  # Scrolle automatisch nach unten
                self.text_tracert_output.update_idletasks()
                self.text_tracert_output.config(state=tk.DISABLED)

            current_process2.stdout.close()
            current_process2.wait()
            self.text_tracert_output.config(state=tk.NORMAL)
            self.text_tracert_output.insert(
                tk.END, "\nTracert-Prozess abgeschlossen.\n"
            )
            self.text_tracert_output.config(state=tk.DISABLED)
            current_process2 = (
                None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
            )
        except Exception as e:
            messagebox.showerror(
                "Fehler", f"Fehler beim Starten des Tracert-Prozesses: {e}"
            )
            current_process2 = None

    def stop_tracert(self):
        """Stoppt den laufenden Tracert-Prozess."""
        global current_process2
        if current_process2 and current_process2.poll() is None:

            def terminate_process(proc):
                try:
                    proc.terminate()
                    proc.wait()
                    self.text_tracert_output.config(state=tk.NORMAL)
                    self.text_tracert_output.insert(
                        tk.END, "\nTracert-Prozess wurde gestoppt.\n"
                    )
                    self.text_tracert_output.see(
                        tk.END
                    )  # Scrolle automatisch nach unten
                    self.text_tracert_output.update_idletasks()
                    self.text_tracert_output.config(state=tk.DISABLED)
                    global current_process2
                    current_process2 = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
                except Exception as e:
                    messagebox.showerror(
                        "Fehler", f"Fehler beim Stoppen des Tracert-Prozesses: {e}"
                    )

                    current_process2 = None

            threading.Thread(target=terminate_process, args=(current_process2,)).start()

    def clear_tracert_output(self):
        """Löscht die Ausgabe der Tracert-Textbox."""
        self.text_tracert_output.config(state=tk.NORMAL)
        self.text_tracert_output.delete(1.0, tk.END)
        self.text_tracert_output.config(state=tk.DISABLED)

    # -----------------tracert tab methods end-----------------
    
    def run_nslookup(self):
        domain = self.entry_domain.get().strip()
        query_type = self.combobox_query_type.get()

        if not domain:
            messagebox.showerror("Fehler", "Bitte geben Sie eine Domain ein.")
            return

        if query_type == "ohne":
            command = f"nslookup {domain}"
        else:
            command = f"nslookup -query={query_type} {domain}"

        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            output = result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            output = f"Fehler: {e}"

        self.text_nslookup_output.config(state=tk.NORMAL)
        self.text_nslookup_output.delete(1.0, tk.END)
        self.text_nslookup_output.insert(tk.END, output)
        self.text_nslookup_output.config(state=tk.DISABLED)


if __name__ == "__main__":
    try:
        # Überprüfen, ob das Programm mit Administratorrechten ausgeführt wird
        if not is_admin():
            # Programm neu starten mit Administratorrechten
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        else:
            print("Adminrechte i.O.")
            root = tk.Tk()
            app = NetworkToolsApp(root)
            root.mainloop()
    except Exception as e:
        print("---------------")
        print("Fehler:")
        print(e)
        print("---------------")

        messagebox.showerror(
            "Kritischer Fehler", f"Das Programm konnte nicht gestartet werden: {e}"
        )
        sys.exit(1)
