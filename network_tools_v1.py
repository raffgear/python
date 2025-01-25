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

# Globale Variablen für den Ping-Tab
command_history = []  # Befehlsverlauf
history_index = -1  # Index für den Befehlsverlauf
current_process = None  # Aktueller Ping-Prozess


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
            self.font = ("Arial", 12)
            self.font10 = ("Arial", 10)
            self.label_font = ("Arial", 12, "bold")
            self.large_font = ("Arial", 24, "bold")

            # Stil für ttk-Widgets
            self.style = ttk.Style()
            self.style.configure("TLabel", font=self.label_font)
            self.style.configure("TButton", font=self.font)
            self.style.configure("TEntry", font=self.font)
            self.style.configure("TCombobox", font=self.font)

            # Überprüfen, ob das Programm mit Administratorrechten ausgeführt wird
            if not is_admin():
                messagebox.showerror(
                    "Fehlende Berechtigungen",
                    "Das Programm muss mit Administratorrechten ausgeführt werden.",
                )
                sys.exit(1)

            # Notebook (Tabs) erstellen
            self.notebook = ttk.Notebook(root)
            self.notebook.pack(expand=True, fill="both")

            # Tab für Netzwerkkarten-Daten
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

            # Button zum Speichern des Profils
            self.button_save_profile = ttk.Button(
                self.frame_profile,
                text="Profil speichern",
                command=self.save_profile,
                style="TButton",
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

            # Neuer Tab für externe IP
            self.tab_external_ip = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_external_ip, text="Ext. IP")

            # Anzeigefeld für die externe IP
            self.label_external_ip = ttk.Label(
                self.tab_external_ip,
                text="Öffentliche IP-Adresse:",
                style="TLabel",
                font=self.large_font,
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

            # Button zum Abrufen der öffentlichen IP
            self.button_get_external_ip = ttk.Button(
                self.tab_external_ip,
                text="Öffentliche IP anzeigen",
                command=self.get_external_ip,
                style="TButton",
            )
            self.button_get_external_ip.pack(pady=10)

            # Neuer Tab für Ping
            self.tab_ping = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_ping, text="Ping")

            # Eingabefeld für Befehle und Senden-Button
            self.top_frame = tk.Frame(self.tab_ping)
            self.top_frame.pack(fill=tk.X, padx=5, pady=5)

            self.command_entry = tk.Entry(self.top_frame, font=("Courier", 10))
            self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.command_entry.insert(0, "ping 8.8.8.8")  # Voreingestellter Befehl
            self.command_entry.bind("<Return>", lambda event: self.execute_command())
            self.command_entry.bind("<Up>", self.show_previous_command)
            self.command_entry.bind("<Down>", self.show_next_command)

            self.send_button = tk.Button(
                self.top_frame,
                text="Senden",
                command=self.execute_command,
                font=("Courier", 10),
            )
            self.send_button.pack(side=tk.LEFT, padx=5)

            # Abbrechen-Button
            self.stop_button = tk.Button(
                self.top_frame,
                text="Abbrechen",
                command=self.stop_command,
                font=("Courier", 10),
            )
            self.stop_button.pack(side=tk.LEFT, padx=5)

            # Verlauf-Label und Combobox
            self.history_label = tk.Label(
                self.tab_ping, text="Verlauf", font=("Courier", 10)
            )
            self.history_label.pack(anchor=tk.W, padx=5)

            self.history_combobox = ttk.Combobox(self.tab_ping, font=("Courier", 10))
            self.history_combobox.pack(fill=tk.X, padx=5, pady=5)
            self.history_combobox.bind("<<ComboboxSelected>>", self.on_history_select)

            # ScrolledText-Widget für die Ausgabe
            self.output_text = scrolledtext.ScrolledText(
                self.tab_ping, wrap=tk.WORD, font=("Courier", 8)
            )
            self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.output_text.config(state=tk.DISABLED)

            # Fenstergröße anpassen
            self.root.update_idletasks()
            self.root.minsize(self.root.winfo_width(), self.root.winfo_height())

        except Exception as e:
            messagebox.showerror(
                "Kritischer Fehler", f"Das Programm konnte nicht gestartet werden: {e}"
            )
            sys.exit(1)

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
            nic.EnableDHCP()
            # DNS-Server auch auf DHCP zurücksetzen
            nic.SetDNSServerSearchOrder()  # Leere Liste setzt DNS auf DHCP zurück
            # Gateway zurücksetzen
            nic.SetGateways(DefaultIPGateway=[])  # Leere Liste setzt Gateway zurück
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

    def execute_command(self):
        """Führt den eingegebenen Befehl aus und zeigt die Ausgabe in Echtzeit an."""
        global history_index, current_process

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


if __name__ == "__main__":
    try:
        # Überprüfen, ob das Programm mit Administratorrechten ausgeführt wird
        if not is_admin():
            # Programm neu starten mit Administratorrechten
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        else:
            root = tk.Tk()
            app = NetworkToolsApp(root)
            root.mainloop()
    except Exception as e:
        messagebox.showerror(
            "Kritischer Fehler", f"Das Programm konnte nicht gestartet werden: {e}"
        )
