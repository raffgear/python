import customtkinter as ctk
from tkinter import ttk
from tkinter import messagebox, scrolledtext, filedialog
import tkinter as tk
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
from speedtest import Speedtest
import random
import socket
import psutil
from ipaddress import IPv4Network
import time
import concurrent.futures
import webbrowser
import scapy.all as scapy
from fpdf import FPDF
import logging
import ipaddress

# Globale Variablen für den Ping-Tab
command_history = []  # Befehlsverlauf
history_index = -1  # Index für den Befehlsverlauf
current_process = None  # Aktueller Ping-Prozess
current_process2 = None  # Aktueller Tracert-Prozess

# Globale Variablen für den Infotext je Tab
info_text = {
    "IPConfig": "Hier können Sie die Netzwerkkarten-Daten anzeigen und bearbeiten.",
    "Ext. IP": "Hier können Sie Ihre öffentliche IP-Adresse abrufen.",
    "Ping": "Hier können Sie einen Ping an eine IP-Adresse oder Domain senden.",
    "Tracert": "Hier können Sie einen Traceroute an eine IP-Adresse oder Domain senden.",
    "NSLookup": "Hier können Sie DNS-Abfragen durchführen.",
    "Speedtest": "Hier können Sie einen Speedtest Ihrer Internetverbindung durchführen.",
    "Porttest": "Prüft alle 5 Sekunden ob TCP-Ports bei einer IP-Adresse erreichbar sind.\n Ports mit Leerzeichen voneinander trennen.",
    "IP-Scan": "Hier können Sie Ihr Netzwerk nach Geräten scannen.",
    "Port-Scan": "Hier können Sie die offenen TCP-Ports einer IP-Adresse scannen.",
}


def is_admin():
    """Überprüft, ob das Programm mit Administratorrechten ausgeführt wird."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def setup_logger():
    logging.basicConfig(
        level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s"
    )


def log_exception():
    """Loggt die letzte Exception mit Stacktrace."""
    logging.error("Ein Fehler ist aufgetreten:", exc_info=True)


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
            self.root.title("Network Tools by Ralph")
            self.checking = False
            self.timer_id = None
            self.info_text = ""
            self.animation_job = None

            # Schriftgröße und Stil
            self.font = ("Calibri", 12)
            self.font10 = ("Calibri", 10)
            self.font16 = ("Calibri", 16)
            self.font16bold = ("Calibri", 16, "bold")
            self.label_font = ("Calibri", 12, "bold")
            self.large_font = ("Calibri", 24, "bold")

            self.scanning_active_ps = False
            self.start_time_ps = None
            self.open_ports_ps = []

            self.anim_rect_x_ps = 0
            self.anim_rect_direction_ps = 1
            self.anim_rect_width_ps = 50
            self.anim_rect_height_ps = 20
            self.canvas_width_ps = 200
            self.canvas_height_ps = 30
            self.anim_canvas_ps = None

            self.scan_results_ipsc = []

            ####################################################################
            # Notebook (Tabs) erstellen
            ####################################################################
            def on_tab_change(event):
                self.info_text = self.info_label.configure(text=info_text[event])
                # print(f"Tab gewechselt! Neuer Tab: {event.widget.select()}")

            self.notebook = ctk.CTkTabview(root)
            self.notebook.pack(expand=True, fill="both")

            # self.notebook._segmented_button(command=on_tab_change)

            # Eigene Funktion für den Tabwechsel setzen, ohne den Standardmechanismus zu brechen
            original_command = (
                self.notebook._segmented_button._command
            )  # Speichert das Original-Kommando

            def tab_change_wrapper(value):
                original_command(value)  # Führt den normalen Tabwechsel aus
                on_tab_change(value)  # Führt unsere zusätzliche Logik aus

            self.notebook._segmented_button.configure(command=tab_change_wrapper)

            # Infoleiste erstellen
            self.info_frame = ctk.CTkFrame(root, corner_radius=0, height=10)
            self.info_frame.pack(side="bottom", fill="x")

            self.info_label = ctk.CTkLabel(
                self.info_frame,
                text=self.info_text,
                fg_color="transparent",
                font=self.fonts(16),
            )
            # initialisieren des Infotexts mit dem ersten Tab
            self.info_text = self.info_label.configure(text=info_text["IPConfig"])

            self.info_label.pack(pady=2, padx=5, anchor="center")

            # Tab für Netzwerkkarten-Daten
            self.tab_network_interfaces = self.notebook.add("IPConfig")

            # Dropdown für Netzwerkkarten-Auswahl
            self.label_select_interface = ctk.CTkLabel(
                self.tab_network_interfaces,
                text="Wählen Sie eine Netzwerkkarte:",
                font=self.font16bold,
            )
            self.label_select_interface.pack(pady=10)

            self.selected_interface = ctk.StringVar()
            self.dropdown_interfaces = ctk.CTkComboBox(
                self.tab_network_interfaces,
                variable=self.selected_interface,
                width=400,
                command=self.on_interface_select,
            )
            self.dropdown_interfaces.pack(pady=10)

            # Optionsfeld für DHCP oder statische IP in einer Zeile
            self.frame_dhcp = ctk.CTkFrame(self.tab_network_interfaces)
            self.frame_dhcp.pack(pady=10)

            self.label_dhcp = ctk.CTkLabel(
                self.frame_dhcp, text="IP-Konfiguration:", font=self.font16bold
            )
            self.label_dhcp.pack(side="left", padx=5)

            self.dhcp_mode = ctk.StringVar(value="DHCP")  # Standardmäßig DHCP
            self.radio_dhcp = ctk.CTkRadioButton(
                self.frame_dhcp,
                text="DHCP",
                variable=self.dhcp_mode,
                value="DHCP",
                command=self.toggle_dhcp_mode,
            )
            self.radio_dhcp.pack(side="left", padx=5)
            self.radio_static = ctk.CTkRadioButton(
                self.frame_dhcp,
                text="Statisch",
                variable=self.dhcp_mode,
                value="Statisch",
                command=self.toggle_dhcp_mode,
            )
            self.radio_static.pack(side="left", padx=5)

            # Felder für Netzwerkkarten-Daten
            self.frame_fields = ctk.CTkFrame(self.tab_network_interfaces)
            self.frame_fields.pack(pady=10)

            # IP-Adresse
            self.label_ip = ctk.CTkLabel(
                self.frame_fields, text="IP-Adresse:", font=self.font16bold
            )
            self.label_ip.grid(row=0, column=0, padx=5, pady=5, sticky="w")
            self.entry_ip = ctk.CTkEntry(self.frame_fields, width=300, state="readonly")
            self.entry_ip.grid(row=0, column=1, padx=5, pady=5)

            # Subnetzmaske
            self.label_subnet = ctk.CTkLabel(
                self.frame_fields, text="Subnetzmaske:", font=self.font16bold
            )
            self.label_subnet.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.entry_subnet = ctk.CTkEntry(
                self.frame_fields, width=300, state="readonly"
            )
            self.entry_subnet.grid(row=1, column=1, padx=5, pady=5)

            # Gateway
            self.label_gateway = ctk.CTkLabel(
                self.frame_fields, text="Gateway:", font=self.font16bold
            )
            self.label_gateway.grid(row=2, column=0, padx=5, pady=5, sticky="w")
            self.entry_gateway = ctk.CTkEntry(
                self.frame_fields, width=300, state="readonly"
            )
            self.entry_gateway.grid(row=2, column=1, padx=5, pady=5)

            # DNS-Server
            self.label_dns = ctk.CTkLabel(
                self.frame_fields, text="DNS-Server:", font=self.font16bold
            )
            self.label_dns.grid(row=3, column=0, padx=5, pady=5, sticky="w")
            self.entry_dns = ctk.CTkEntry(
                self.frame_fields, width=300, state="readonly"
            )
            self.entry_dns.grid(row=3, column=1, padx=5, pady=5)

            # Button-Frame
            self.frame_buttons = ctk.CTkFrame(self.tab_network_interfaces)
            self.frame_buttons.pack(pady=20)

            # Button zum Übernehmen der Einstellungen
            self.button_apply = ctk.CTkButton(
                self.frame_buttons,
                text="Übernehmen",
                command=self.apply_settings,
            )
            self.button_apply.pack(side="left", padx=10)

            # Button zum Aktualisieren der Netzwerkkarten-Daten
            self.button_refresh = ctk.CTkButton(
                self.frame_buttons,
                text="Aktualisieren",
                command=self.refresh_network_interfaces,
            )
            self.button_refresh.pack(side="left", padx=10)

            # Rahmen für Profile
            self.frame_profile = ctk.CTkFrame(self.tab_network_interfaces)
            self.frame_profile.pack(pady=1, padx=10, fill="x")

            # Profilname Eingabefeld
            self.label_profile_name = ctk.CTkLabel(
                self.frame_profile, text="Profilname:", font=self.font16bold
            )
            self.label_profile_name.pack(pady=5)

            self.entry_profile_name = ctk.CTkEntry(self.frame_profile, width=300)
            self.entry_profile_name.pack(pady=5)
            self.entry_profile_name.bind("<KeyRelease>", self.toggle_save_button)

            # Button zum Speichern des Profils
            self.button_save_profile = ctk.CTkButton(
                self.frame_profile,
                text="Profil speichern",
                command=self.save_profile,
                state="disabled",
            )
            self.button_save_profile.pack(pady=5)

            # Dropdown für Profilauswahl
            self.label_select_profile = ctk.CTkLabel(
                self.frame_profile, text="Wählen Sie ein Profil:", font=self.font16bold
            )
            self.label_select_profile.pack(pady=5)

            self.selected_profile = ctk.StringVar()
            self.dropdown_profiles = ctk.CTkComboBox(
                self.frame_profile,
                variable=self.selected_profile,
                width=300,
                command=self.on_profile_select,
            )
            self.dropdown_profiles.pack(pady=5)

            # Button zum Löschen des Profils
            self.button_delete_profile = ctk.CTkButton(
                self.frame_profile,
                text="Profil löschen",
                command=self.delete_profile,
            )
            self.button_delete_profile.pack(pady=5)

            # Netzwerkkarten-Daten beim Start laden
            self.load_network_interfaces()

            # Profile beim Start laden
            self.load_profiles()
            ####################################################################
            # Neuer Tab für externe IP
            ####################################################################
            self.tab_external_ip = self.notebook.add("Ext. IP")

            # Anzeigefeld für die externe IP
            self.label_external_ip = ctk.CTkLabel(
                self.tab_external_ip,
                text="Öffentliche IP-Adresse:",
                font=self.font16bold,
            )
            self.label_external_ip.pack(pady=10)

            self.label_ip_display = ctk.CTkLabel(
                self.tab_external_ip,
                text="",
                font=self.fonts(60, True),
            )
            self.label_ip_display.pack(pady=10, fill="x")
            self.label_ip_display.bind("<Double-1>", self.copy_ip_to_clipboard)

            self.label_ipv6_display = ctk.CTkLabel(
                self.tab_external_ip,
                text="",
                font=self.fonts(40, True),
            )
            self.label_ipv6_display.pack(pady=10, fill="x")
            self.label_ipv6_display.bind("<Double-1>", self.copy_ipv6_to_clipboard)

            # Button zum Abrufen der öffentlichen IP
            self.button_get_external_ip = ctk.CTkButton(
                self.tab_external_ip,
                text="Öffentliche IP anzeigen",
                command=self.get_external_ip,
            )
            self.button_get_external_ip.pack(pady=10)

            ####################################################################
            # Neuer Tab für Ping
            ####################################################################
            self.tab_ping = self.notebook.add("Ping")

            # Eingabefeld für die IP-Adresse oder Domain
            self.label_ping_ip = ctk.CTkLabel(
                self.tab_ping, text="IP-Adresse oder Domain:", font=self.font16bold
            )
            self.label_ping_ip.pack(pady=10)

            # Frame für die entry und dropdownmenu
            self.frame_ping_frame = ctk.CTkFrame(self.tab_ping)
            self.frame_ping_frame.pack(pady=10, padx=10)

            self.entry_ping_ip = ctk.CTkEntry(self.frame_ping_frame, width=300)
            self.entry_ping_ip.pack(pady=10, side="left")
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

            self.combobox_test_addresses_ping = ctk.CTkComboBox(
                self.frame_ping_frame,
                values=test_addresses,
                state="readonly",
                width=300,
                command=self.update_ip_entry_ping,
            )
            self.combobox_test_addresses_ping.pack(pady=10, padx=10, side="right")
            self.combobox_test_addresses_ping.set(
                "Wählen Sie eine Adresse"
            )  # Standardtext

            # Frame für die Radiobuttons
            self.frame_ping_options = ctk.CTkFrame(self.tab_ping)
            self.frame_ping_options.pack(pady=10)

            # Variable für die Radiobuttons
            self.ping_option = ctk.StringVar(value="count")

            # Radiobutton für kontinuierliches Ping (-t)
            self.radio_ping_continuous = ctk.CTkRadioButton(
                self.frame_ping_options,
                text="-t (kontinuierlich)",
                variable=self.ping_option,
                value="continuous",
            )
            self.radio_ping_continuous.pack(side="left", padx=5)

            # Radiobutton für Anzahl der Ping-Pakete (-n)
            self.radio_ping_count = ctk.CTkRadioButton(
                self.frame_ping_options,
                text="Anzahl der Ping-Pakete:",
                variable=self.ping_option,
                value="count",
            )
            self.radio_ping_count.pack(side="left", padx=5)

            # Spinbox für die Anzahl der Ping-Pakete

            # Liste mit Zahlen von 1 bis 20 erstellen
            self.number_list = [str(i) for i in range(1, 21)]

            # CTkOptionMenu erstellen
            self.ping_count = ctk.IntVar(value=4)
            self.spinbox_ping_count = ctk.CTkOptionMenu(
                self.frame_ping_options,
                values=self.number_list,
                variable=self.ping_count,
            )
            self.spinbox_ping_count.pack(pady=20)

            # Standardwert setzen (z. B. "1")
            self.spinbox_ping_count.set("4")

            self.spinbox_ping_count.pack(side="left", padx=5)

            # Button-Frame für Ping
            self.frame_ping_buttons = ctk.CTkFrame(self.tab_ping)
            self.frame_ping_buttons.pack(pady=10)

            # Button zum Starten des Ping
            self.button_ping_start = ctk.CTkButton(
                self.frame_ping_buttons,
                text="Starten",
                command=self.start_ping,
            )
            self.button_ping_start.pack(side="left", padx=5)

            # Button zum Stoppen des Ping
            self.button_ping_stop = ctk.CTkButton(
                self.frame_ping_buttons,
                text="Stoppen",
                command=self.stop_ping,
            )
            self.button_ping_stop.pack(side="left", padx=5)

            # Button zum Löschen der Ausgabe
            self.button_ping_clear = ctk.CTkButton(
                self.frame_ping_buttons,
                text="Löschen",
                command=self.clear_ping_output,
            )
            self.button_ping_clear.pack(side="left", padx=5)

            # Textbox für die Ping-Ausgabe
            self.text_ping_output = scrolledtext.ScrolledText(
                self.tab_ping,
                width=30,  # Breite der Textbox (in Zeichen)
                height=15,  # Höhe der Textbox (in Zeilen)
                wrap="word",
                font=self.font10,
            )
            self.text_ping_output.tag_configure("myTag", lmargin1=10, lmargin2=10)

            self.text_ping_output.pack(pady=10, padx=10, fill="both", expand=True)

            ####################################################################
            # Neuer Tab für traceroute
            ####################################################################
            self.tab_traceroute = self.notebook.add("Tracert")

            # Eingabefeld für die IP-Adresse oder Domain
            self.label_tracert_ip = ctk.CTkLabel(
                self.tab_traceroute,
                text="IP-Adresse oder Domain:",
                font=self.font16bold,
            )
            self.label_tracert_ip.pack(padx=10, pady=10)

            # Neuer Frame für traceroute ip und dropdown
            self.frame_tracert_frame = ctk.CTkFrame(self.tab_traceroute)
            self.frame_tracert_frame.pack(pady=10, padx=10)

            self.entry_tracert_ip = ctk.CTkEntry(self.frame_tracert_frame, width=300)
            self.entry_tracert_ip.pack(pady=10, side="left")
            self.entry_tracert_ip.insert(0, "8.8.8.8")  # Vorbelegen mit 8.8.8.8
            self.entry_tracert_ip.focus_set()
            self.entry_tracert_ip.bind("<Return>", lambda e: self.start_tracert())

            self.combobox_test_addresses_tracert = ctk.CTkComboBox(
                self.frame_tracert_frame,
                values=test_addresses,
                state="readonly",
                width=300,
                command=self.update_ip_entry_tracert,
            )
            self.combobox_test_addresses_tracert.pack(pady=10, padx=10, side="right")
            self.combobox_test_addresses_tracert.set(
                "Wählen Sie eine Adresse"
            )  # Standardtext

            # Button-Frame für tracert
            self.frame_tracert_buttons = ctk.CTkFrame(self.tab_traceroute)
            self.frame_tracert_buttons.pack(pady=10)

            # Button zum Starten des tracert
            self.button_tracert_start = ctk.CTkButton(
                self.frame_tracert_buttons,
                text="Starten",
                command=self.start_tracert,
            )
            self.button_tracert_start.pack(side="left", padx=5)

            # Button zum Stoppen des tracert
            self.button_tracert_stop = ctk.CTkButton(
                self.frame_tracert_buttons,
                text="Stoppen",
                command=self.stop_tracert,
            )
            self.button_tracert_stop.pack(side="left", padx=5)

            # Button zum Löschen der Ausgabe
            self.button_tracert_clear = ctk.CTkButton(
                self.frame_tracert_buttons,
                text="Löschen",
                command=self.clear_tracert_output,
            )
            self.button_tracert_clear.pack(side="left", padx=5)

            # Textbox für die Ping-Ausgabe
            self.text_tracert_output = scrolledtext.ScrolledText(
                self.tab_traceroute,
                width=30,  # Breite der Textbox (in Zeichen)
                height=15,  # Höhe der Textbox (in Zeilen)
                wrap="word",
                font=self.font10,
            )
            self.text_tracert_output.pack(pady=10, padx=10, fill="both", expand=True)

            self.text_tracert_output.tag_configure("myTag2", lmargin1=10, lmargin2=10)

            #################################################################
            # Neuer Tab für nslookup
            #################################################################
            self.tab_nslookup = self.notebook.add("NSLookup")

            # Label für die Domain-Eingabe
            self.label_domain = ctk.CTkLabel(
                self.tab_nslookup,
                text="IP-Adresse oder Domain:",
                font=self.font16bold,
            )
            self.label_domain.pack(pady=10, padx=10)

            # Eingabefeld für die Domain
            # Neuer Frame für nslookup ip und dropdown
            self.frame_nslookup_frame = ctk.CTkFrame(self.tab_nslookup)
            self.frame_nslookup_frame.pack(pady=10, padx=10)

            self.entry_nslookup_ip = ctk.CTkEntry(self.frame_nslookup_frame, width=300)
            self.entry_nslookup_ip.pack(pady=10, side="left")
            self.entry_nslookup_ip.insert(0, "google.com")  # Vorbelegen mit google.com

            self.combobox_test_addresses_nslookup = ctk.CTkComboBox(
                self.frame_nslookup_frame,
                values=test_addresses,
                state="readonly",
                width=300,
                command=self.update_ip_entry_nslookup,
            )
            self.combobox_test_addresses_nslookup.pack(pady=10, padx=10, side="right")
            self.combobox_test_addresses_nslookup.set(
                "Wählen Sie eine Adresse"
            )  # Standardtext

            # Label für die Abfragetyp-Auswahl
            self.label_query_type = ctk.CTkLabel(self.tab_nslookup, text="Abfragetyp:")
            self.label_query_type.pack(pady=5, padx=10, anchor="w")

            # Combobox für die Abfragetyp-Auswahl
            self.combobox_query_type = ctk.CTkComboBox(
                self.tab_nslookup,
                values=["ohne", "MX", "NS", "TEXT", "SOA"],
                state="readonly",
            )
            self.combobox_query_type.pack(pady=5, padx=10, anchor="w")
            self.combobox_query_type.set(
                "ohne"
            )  # Standardmäßig den ersten Eintrag auswählen

            # Button zum Starten der Abfrage
            self.button_nslookup = ctk.CTkButton(
                self.tab_nslookup, text="Abfrage starten", command=self.run_nslookup
            )
            self.button_nslookup.pack(pady=5, padx=10, anchor="w")

            # Textbox für die Ausgabe
            self.text_nslookup_output = scrolledtext.ScrolledText(
                self.tab_nslookup, width=80, height=20, wrap="word"
            )
            self.text_nslookup_output.pack(pady=10, padx=10, fill="both", expand=True)
            self.text_nslookup_output.tag_configure(
                "myTag3",
                lmargin1=10,
                lmargin2=10,
            )
            ####################################################################
            # Neuer Tab für speedtest
            ####################################################################
            self.tab_speedtest = self.notebook.add("Speedtest")

            # Label für Titel
            self.title_label = ctk.CTkLabel(
                self.tab_speedtest, text="Internet Speedtest", font=self.fonts(24, True)
            )
            self.title_label.pack(pady=10)

            # Button für Speedtest
            self.start_button = ctk.CTkButton(
                self.tab_speedtest, text="Start Speedtest", command=self.start_speedtest
            )
            self.start_button.pack(pady=10)

            # Canvas für Circular Progress
            self.canvas = ctk.CTkCanvas(
                self.tab_speedtest,
                width=300,
                height=300,
                highlightthickness=0,
                bg=self.title_label["bg"],
            )

            self.canvas.pack(pady=20, side="top")

            # Frame für tabellarische Ergebnisse
            self.result_frame = ctk.CTkFrame(self.tab_speedtest, width=420)
            self.result_frame.pack(pady=40, padx=40)

            # Initialisiere die Tabelle mit leeren Labels
            self.labels = {}

            # Parameter und Einheiten
            parameters = [
                ("Download-Speed", "MBit/s"),
                ("Upload-Speed", "MBit/s"),
                ("Ping", "ms"),
            ]

            # Erzeuge die Labels, aber verstecke sie initial
            for row, (param, unit) in enumerate(parameters, start=1):
                # Linke Spalte: Parameter
                label_param = ctk.CTkLabel(
                    self.result_frame,
                    text="",
                    font=self.fonts(30),
                    anchor="e",  # Rechtsbündig
                )
                label_param.grid(row=row, column=0, padx=6, pady=6, sticky="e")
                # label_param.grid_remove()  # Verstecke das Label initial
                self.labels[f"row{row}_col0"] = label_param

                # Rechte Spalte: Wert (initial leer)
                label_value = ctk.CTkLabel(
                    self.result_frame,
                    text="",  # Initial leer
                    font=self.fonts(46, True),
                    # Linksbündig
                )
                label_value.grid(row=row, column=1, padx=6, pady=6, sticky="w")
                # label_value.grid_remove()  # Verstecke das Label initial
                self.labels[f"row{row}_col1"] = label_value

            ####################################################################
            # Neuer Tab für porttest
            ####################################################################
            # Annahme: self.notebook ist bereits initialisiert und unterstützt .add() für Tabs.
            self.tab_porttest = self.notebook.add("Porttest")

            # Konfiguration der Spalten:
            # Spalte 0: Labels (feste Breite)
            # Spalte 1: Entries, die sich ausdehnen (sticky "ew")
            self.tab_porttest.grid_columnconfigure(0, weight=0)
            self.tab_porttest.grid_columnconfigure(1, weight=1)

            # ---------------------------
            # Zeile 0: IP-Adresse Label und Entry
            # ---------------------------
            ctk.CTkLabel(self.tab_porttest, text="IP-Adresse:").grid(
                row=0, column=0, padx=10, pady=5, sticky="e"
            )

            self.entry_ip_address = ctk.CTkEntry(self.tab_porttest, width=300)
            self.entry_ip_address.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
            self.entry_ip_address.insert(0, "192.168.178.1")
            self.entry_ip_address.bind(
                "<KeyRelease>", lambda event: self.validate_input()
            )

            # ---------------------------
            # Zeile 1: Zu prüfende Ports Label und Entry
            # ---------------------------
            ctk.CTkLabel(self.tab_porttest, text="Zu prüfende Ports:").grid(
                row=1, column=0, padx=10, pady=5, sticky="e"
            )

            self.entry_additional_ports = ctk.CTkEntry(self.tab_porttest, width=300)
            self.entry_additional_ports.grid(
                row=1, column=1, padx=10, pady=5, sticky="ew"
            )
            self.entry_additional_ports.bind(
                "<KeyRelease>", lambda event: self.validate_input()
            )

            # ---------------------------
            # Zeile 2: Button "Ports löschen"
            # ---------------------------
            self.btn_clear_ports = ctk.CTkButton(
                self.tab_porttest, text="Ports löschen", command=self.clear_ports
            )
            self.btn_clear_ports.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

            # ---------------------------
            # Zeile 3: Checkboxes für Port 443 und Port 8802
            # ---------------------------
            self.var_port_443 = ctk.BooleanVar()
            self.chk_port_443 = ctk.CTkCheckBox(
                self.tab_porttest,
                text="Port 443",
                variable=self.var_port_443,
                command=lambda: self.toggle_port_in_entry(443, self.var_port_443),
            )
            self.chk_port_443.grid(row=3, column=0, padx=10, pady=5, sticky="w")

            self.var_port_8802 = ctk.BooleanVar()
            self.chk_port_8802 = ctk.CTkCheckBox(
                self.tab_porttest,
                text="Port 8802",
                variable=self.var_port_8802,
                command=lambda: self.toggle_port_in_entry(8802, self.var_port_8802),
            )
            self.chk_port_8802.grid(row=3, column=1, padx=10, pady=5, sticky="w")

            # ---------------------------
            # Zeile 4: Button "Check Starten"
            # ---------------------------
            self.btn_check = ctk.CTkButton(
                self.tab_porttest,
                text="Check Starten",
                command=self.start_checking,
                state="disabled",
            )
            self.btn_check.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

            # ---------------------------
            # Zeile 5: Treeview für Ergebnisse
            # ---------------------------
            # Damit der Treeview-Bereich bei Bedarf mitwächst:
            self.tab_porttest.grid_rowconfigure(5, weight=1)
            styleT = ttk.Style()
            styleT.configure("ST.Treeview", font=self.fonts(14), rowheight=30)
            styleTH = ttk.Style()
            styleTH.configure("Treeview.Heading", font=self.fonts(16, True))
            self.tree = ttk.Treeview(
                self.tab_porttest,
                columns=("Port", "Status"),
                show="headings",
                height=4,
                style="ST.Treeview",
            )

            self.tree.heading(
                "Port",
                text="Port",
            )
            self.tree.heading(
                "Status",
                text="Status",
            )
            self.tree.column("Port", width=120, anchor="center")
            self.tree.column("Status", width=200, anchor="center")
            self.tree.grid(
                row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew"
            )

            # Konfiguration der Tags für farbliche Markierung
            self.tree.tag_configure(
                "green", background="lightgreen", foreground="black"
            )
            self.tree.tag_configure("red", background="lightcoral", foreground="black")

            ####################################################################
            # Neuer Tab für ip-scan
            ####################################################################

            # Tab "IP-Scan" hinzufügen
            self.tab_ip_scan = self.notebook.add("IP-Scan")

            # Konfiguriere die Spalten im Tab:
            # Spalte 0: Labels (feste Breite, linksbündig)
            # Spalte 1: Eingabefelder (dehnbar, linksbündig)
            # Spalte 2: Buttons (feste Breite, rechtsbündig)
            self.tab_ip_scan.grid_columnconfigure(0, weight=0, minsize=30)
            self.tab_ip_scan.grid_columnconfigure(1, weight=0)
            self.tab_ip_scan.grid_columnconfigure(2, weight=0)

            # --- Zeile 0: Netzwerk ---
            self.interface_label_ipsc = ctk.CTkLabel(
                self.tab_ip_scan, text="Netzwerk:", width=20, anchor="w"
            )
            self.interface_label_ipsc.grid(row=0, column=0, padx=10, pady=5, sticky="w")

            self.interface_combobox_ipsc = ctk.CTkComboBox(
                self.tab_ip_scan,
                values=self.get_network_interfaces_ipsc(),
                # variable=self.selected_interface,
                width=360,
                command=lambda event: self.update_ip_range_ipsc(),
            )

            self.interface_combobox_ipsc.grid(
                row=0, column=1, padx=10, pady=5, sticky="w", columnspan=2
            )

            # --- Zeile 1: Start-IP ---
            self.start_ip_label_ipsc = ctk.CTkLabel(
                self.tab_ip_scan, text="Start-IP:", width=14, anchor="w"
            )
            self.start_ip_label_ipsc.grid(row=1, column=0, padx=10, pady=5, sticky="w")

            self.start_ip_entry_ipsc = ctk.CTkEntry(self.tab_ip_scan, width=200)
            self.start_ip_entry_ipsc.grid(row=1, column=1, padx=10, pady=5, sticky="w")

            # --- Zeile 2: End-IP ---
            self.end_ip_label_ipsc = ctk.CTkLabel(
                self.tab_ip_scan, text="End-IP:", width=14, anchor="w"
            )
            self.end_ip_label_ipsc.grid(row=2, column=0, padx=10, pady=5, sticky="w")

            self.end_ip_entry_ipsc = ctk.CTkEntry(self.tab_ip_scan, width=200)
            self.end_ip_entry_ipsc.grid(row=2, column=1, padx=10, pady=5, sticky="w")

            # --- Buttons: in Spalte 2 ---
            # Hier platzieren wir "Scan starten" und "Scan stoppen" in den Zeilen 1 und 2
            self.scan_button_ipsc = ctk.CTkButton(
                self.tab_ip_scan,
                text="Scan starten",
                command=self.start_scan_ipsc,
                state="disabled",
            )
            self.scan_button_ipsc.grid(row=1, column=2, padx=10, pady=5, sticky="e")

            self.stop_button_ipsc = ctk.CTkButton(
                self.tab_ip_scan,
                text="Scan stoppen",
                command=self.stop_scan_ipsc,
                state="disabled",
            )
            self.stop_button_ipsc.grid(row=2, column=2, padx=10, pady=5, sticky="e")

            # --- Zeile 3: Filter-Eingabefeld ---
            self.filter_label_ipsc = ctk.CTkLabel(
                self.tab_ip_scan, text="Filter:", width=10, anchor="w"
            )
            self.filter_label_ipsc.grid(row=3, column=0, padx=10, pady=5, sticky="w")

            self.filter_entry_ipsc = ctk.CTkEntry(self.tab_ip_scan, width=260)
            self.filter_entry_ipsc.grid(row=3, column=1, padx=10, pady=5, sticky="w")
            self.filter_entry_ipsc.bind(
                "<KeyRelease>",
                lambda event: self.filter_results_ipsc(),
            )

            # --- Zeile 4: Treeview für Ergebnisse ---
            self.tree_ipsc = ttk.Treeview(
                self.tab_ip_scan,
                columns=("Name", "IP", "MAC", "Hersteller"),
                show="headings",
                height=10,
            )
            self.tree_ipsc.heading(
                "Name", text="Name", command=lambda: self.sort_treeview_ipsc("Name")
            )
            self.tree_ipsc.heading(
                "IP", text="IP", command=lambda: self.sort_treeview_ipsc("IP")
            )
            self.tree_ipsc.heading(
                "MAC", text="MAC", command=lambda: self.sort_treeview_ipsc("MAC")
            )
            self.tree_ipsc.heading(
                "Hersteller",
                text="Hersteller",
                command=lambda: self.sort_treeview_ipsc("Hersteller"),
            )
            self.tree_ipsc.column("Name", width=110)
            self.tree_ipsc.column("IP", width=70)
            self.tree_ipsc.column("MAC", width=70)
            self.tree_ipsc.column("Hersteller", width=110)
            self.tree_ipsc.grid(
                row=4, column=0, columnspan=3, padx=10, pady=5, sticky="nsew"
            )
            self.tab_ip_scan.grid_rowconfigure(4, weight=1)

            # --- Kontextmenü ---
            self.context_menu_ipsc = tk.Menu(self.tab_ip_scan, tearoff=0)
            self.context_menu_ipsc.add_command(
                label="Öffne HTTP://", command=self.open_http_ipsc
            )
            self.context_menu_ipsc.add_command(
                label="Öffne HTTPS://", command=self.open_https_ipsc
            )
            self.context_menu_ipsc.add_command(
                label="Exportiere als PDF", command=self.export_to_pdf_ipsc
            )
            self.tree_ipsc.bind("<Button-3>", self.show_context_menu_ipsc)

            ####################################################################
            # Neuer Tab für port-scan
            ####################################################################
            # Tab "Port-Scan" hinzufügen
            self.tab_port_scan = self.notebook.add("Port-Scan")
            self.input_frame_ps = ctk.CTkFrame(self.tab_port_scan)
            self.input_frame_ps.pack(padx=10, pady=10, fill="x")

            ctk.CTkLabel(self.input_frame_ps, text="Zielhost:").grid(
                row=0, column=0, padx=5, pady=5, sticky="w"
            )
            self.host_entry_ps = ctk.CTkEntry(
                self.input_frame_ps, placeholder_text="z.B. 192.168.1.1"
            )
            self.host_entry_ps.grid(row=0, column=1, padx=5, pady=5)
            self.host_entry_ps.insert(0, "192.168.178.1")

            ctk.CTkLabel(self.input_frame_ps, text="Startport:").grid(
                row=1, column=0, padx=5, pady=5, sticky="w"
            )
            self.start_port_entry_ps = ctk.CTkEntry(
                self.input_frame_ps, placeholder_text="z.B. 1"
            )
            self.start_port_entry_ps.grid(row=1, column=1, padx=5, pady=5)
            self.start_port_entry_ps.insert(0, "1")

            ctk.CTkLabel(self.input_frame_ps, text="Endport:").grid(
                row=2, column=0, padx=5, pady=5, sticky="w"
            )
            self.end_port_entry_ps = ctk.CTkEntry(
                self.input_frame_ps, placeholder_text="z.B. 1024"
            )
            self.end_port_entry_ps.grid(row=2, column=1, padx=5, pady=5)
            self.end_port_entry_ps.insert(0, "1024")

            self.action_frame_ps = ctk.CTkFrame(self.tab_port_scan)
            self.action_frame_ps.pack(padx=10, pady=10, fill="x")
            self.scan_button_ps = ctk.CTkButton(
                self.action_frame_ps,
                text="Scan",
                command=self.start_scan,
                corner_radius=20,
            )
            self.scan_button_ps.pack(pady=5)

            self.table_frame_ps = ctk.CTkFrame(self.tab_port_scan)
            self.table_frame_ps.pack(padx=10, pady=10, fill="both", expand=True)

            style_ps = ttk.Style()
            style_ps.configure("Treeview", font=("Calibri", 10))
            style_ps.configure("Treeview.Heading", font=("Calibri", 12, "bold"))

            self.table_ps = ttk.Treeview(
                self.table_frame_ps,
                columns=("Port", "Status"),
                show="headings",
                height=15,
            )
            self.table_ps.column("Port", anchor="center", width=100)
            self.table_ps.column("Status", anchor="center", width=100)
            self.table_ps.heading("Port", text="Port", anchor="center")
            self.table_ps.heading("Status", text="Status", anchor="center")
            self.table_ps.pack(fill="both", expand=True)

            ####################################################################
            # Ende Tab für port-scan
            ####################################################################

            # Fenstergröße anpassen
            self.root.update_idletasks()
            self.root.geometry("530x700")

        except Exception as e:
            print(e)
            log_exception()
            messagebox.showerror(
                "Kritischer Fehler", f"Das Programm konnte nicht gestartet werden: {e}"
            )
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            time.sleep(15)
            sys.exit(1)

    def fonts(self, size, b=False):
        """Erstellt eine Schriftart mit der voreingestellten Schrift 'Calibri'."""
        weight = "bold" if b else "normal"
        return ("Calibri", size, weight)

    def toggle_save_button(self, event):
        """Aktiviert oder deaktiviert den 'Profil speichern'-Button basierend auf dem Profilnamen."""
        if self.entry_profile_name.get().strip():
            self.button_save_profile.configure(state=ctk.NORMAL)
        else:
            self.button_save_profile.configure(state=ctk.DISABLED)

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

            # Werte der Combobox aktualisieren
            self.dropdown_interfaces.configure(values=list(self.interfaces.keys()))

            # Zuletzt gewählte Netzwerkkarte laden
            last_selected_interface = self.load_last_selected_interface()
            if last_selected_interface in self.interfaces:
                self.selected_interface.set(last_selected_interface)

            # self.interface_combobox_ipsc.set(last_selected_interface)
            else:
                self.selected_interface.set(
                    list(self.interfaces.keys())[0]
                )  # Setzt den ersten Wert

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
                self.entry_ip.configure(state="normal")
                self.entry_ip.delete(0, ctk.END)
                self.entry_ip.insert(0, interface_data.get("ip", ""))
                self.entry_ip.configure(state="readonly")

                self.entry_subnet.configure(state="normal")
                self.entry_subnet.delete(0, ctk.END)
                self.entry_subnet.insert(0, interface_data.get("subnet", ""))
                self.entry_subnet.configure(state="readonly")

                self.entry_gateway.configure(state="normal")
                self.entry_gateway.delete(0, ctk.END)
                self.entry_gateway.insert(0, interface_data.get("gateway", ""))
                self.entry_gateway.configure(state="readonly")

                self.entry_dns.configure(state="normal")
                self.entry_dns.delete(0, ctk.END)
                self.entry_dns.insert(0, interface_data.get("dns", ""))
                self.entry_dns.configure(state="readonly")

                # DHCP-Modus umschalten
                self.toggle_dhcp_mode()

                # Zuletzt gewählte Netzwerkkarte speichern
                self.save_last_selected_interface(interface_name)
        except Exception as e:
            print(e)
            messagebox.showerror(
                "Fehler", f"Fehler beim Aktualisieren der Netzwerkkarten-Daten: {e}"
            )

    def toggle_dhcp_mode(self):
        """Aktiviert oder deaktiviert die Textfelder basierend auf dem DHCP-Modus."""
        if self.dhcp_mode.get() == "DHCP":
            self.entry_ip.configure(state="readonly")
            self.entry_subnet.configure(state="readonly")
            self.entry_gateway.configure(state="readonly")
            self.entry_dns.configure(state="readonly")
        else:
            self.entry_ip.configure(state="normal")
            self.entry_subnet.configure(state="normal")
            self.entry_gateway.configure(state="normal")
            self.entry_dns.configure(state="normal")

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
            print(e)
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
            print(e)
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
            print(e)
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def load_profiles(self):
        """Lädt die gespeicherten Profile aus einer Datei."""
        try:
            if os.path.exists("profiles.json"):
                with open("profiles.json", "r", encoding="utf-8") as file:
                    profiles = json.load(file)
                    # Werte der Combobox aktualisieren
                    self.dropdown_profiles.configure(values=list(profiles.keys()))
                    return profiles
            return {}
        except Exception as e:
            print(f"Fehler beim Laden der Profile: {e}")
            return {}

    def on_profile_select(self, event=None):
        """Wird aufgerufen, wenn ein Profil ausgewählt wird."""
        print("on_profile_select wird ausgeführt")
        try:
            profile_name = self.selected_profile.get()
            profiles = self.load_profiles()
            if profile_name in profiles:
                profile_data = profiles[profile_name]

                # Netzwerkkarte auswählen
                self.selected_interface.set(profile_data["interface_name"])
                self.on_interface_select()

                # IP-Daten setzen
                self.entry_ip.configure(state="normal")
                self.entry_ip.delete(0, tk.END)
                self.entry_ip.insert(0, profile_data.get("ip", ""))
                self.entry_ip.configure(state="readonly")

                self.entry_subnet.configure(state="normal")
                self.entry_subnet.delete(0, tk.END)
                self.entry_subnet.insert(0, profile_data.get("subnet", ""))
                self.entry_subnet.configure(state="readonly")

                self.entry_gateway.configure(state="normal")
                self.entry_gateway.delete(0, tk.END)
                self.entry_gateway.insert(0, profile_data.get("gateway", ""))
                self.entry_gateway.configure(state="readonly")

                self.entry_dns.configure(state="normal")
                self.entry_dns.delete(0, tk.END)
                self.entry_dns.insert(0, profile_data.get("dns", ""))
                self.entry_dns.configure(state="readonly")

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
            print(e)
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def get_external_ip(self):
        """Ruft die öffentliche IP-Adresse ab und zeigt sie an."""
        try:
            response = requests.get("https://api.ipify.org/?format=json")
            if response.status_code == 200:
                ip_data = response.json()
                external_ip = ip_data.get("ip", "Unbekannt")
                self.label_ip_display.configure(text=external_ip)
            else:
                log_exception()
                messagebox.showerror(
                    "Fehler",
                    "Die öffentliche IP-Adresse konnte nicht abgerufen werden.",
                )
        except Exception as e:
            print(e)
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")
        ##öffentliche ipv6
        try:
            response = requests.get("http://ipecho.net/plain")
            if response.status_code == 200:
                ip_data = response.text

                external_ipv6 = ip_data
                if external_ip != external_ipv6:
                    self.label_ipv6_display.configure(text=external_ipv6)
            else:
                print(e)
                log_exception()
                messagebox.showerror(
                    "Fehler",
                    "Die öffentliche IP-Adresse konnte nicht abgerufen werden.",
                )
        except Exception as e:
            print(e)
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {e}")

    def execute_command(self):
        """Führt den eingegebenen Befehl aus und zeigt die Ausgabe in Echtzeit an."""
        # global history_index, current_process

        # Stoppe den aktuellen Prozess, falls vorhanden
        if current_process and current_process.poll() is None:
            current_process.terminate()
            current_process.wait()

        # Lösche die Ausgabe
        self.output_text.configure(state=ctk.NORMAL)
        self.output_text.delete(1.0, ctk.END)

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
            self.output_text.configure(state=ctk.DISABLED)

        threading.Thread(target=run_command).start()

    def stop_command(self):
        """Stoppt den aktuellen Ping-Prozess."""
        global current_process
        if current_process and current_process.poll() is None:
            current_process.terminate()
            current_process.wait()
            self.output_text.insert(tk.END, "\nProzess abgebrochen.\n")
            self.output_text.configure(state=ctk.DISABLED)

    def show_previous_command(self, event):
        """Zeigt den vorherigen Befehl aus dem Verlauf an."""
        global history_index
        if command_history and history_index > 0:
            history_index -= 1
            self.command_entry.delete(0, ctk.END)
            self.command_entry.insert(0, command_history[history_index])

    def show_next_command(self, event):
        """Zeigt den nächsten Befehl aus dem Verlauf an."""
        global history_index
        if command_history and history_index < len(command_history) - 1:
            history_index += 1
            self.command_entry.delete(0, ctk.END)
            self.command_entry.insert(0, command_history[history_index])

    def update_history_combobox(self):
        """Aktualisiert die Combobox mit dem Befehlsverlauf."""
        self.history_combobox["values"] = command_history

    def on_history_select(self, event):
        """Wird aufgerufen, wenn ein Befehl aus dem Verlauf ausgewählt wird."""
        selected_command = self.history_combobox.get()
        self.command_entry.delete(0, ctk.END)
        self.command_entry.insert(0, selected_command)

    def update_ip_entry(self, event):
        """Aktualisiert das IP-Adressfeld mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses.get()
        self.entry_ping_ip.delete(0, ctk.END)
        self.entry_ping_ip.insert(0, selected_address)

    def update_ip_entry_ping(self, event):
        """Aktualisiert das IP-Adressfeld im Ping-Tab mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses_ping.get()
        self.entry_ping_ip.delete(0, ctk.END)
        self.entry_ping_ip.insert(0, selected_address)

    def update_ip_entry_tracert(self, event):
        """Aktualisiert das IP-Adressfeld im Tracert-Tab mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses_tracert.get()
        self.entry_tracert_ip.delete(0, ctk.END)
        self.entry_tracert_ip.insert(0, selected_address)

    def update_ip_entry_nslookup(self, event):
        """Aktualisiert das IP-Adressfeld im Tracert-Tab mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses_nslookup.get()
        self.entry_nslookup_ip.delete(0, ctk.END)
        self.entry_nslookup_ip.insert(0, selected_address)

    ##############################################################
    # ping tab methods start
    ##############################################################

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
                    self.text_ping_output.configure(state=ctk.NORMAL)
                    self.text_ping_output.insert(tk.END, line, "myTag")
                    self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                    self.text_ping_output.update_idletasks()
                    self.text_ping_output.configure(state=ctk.DISABLED)

                # Warte auf das Ende des Prozesses
                current_process.wait()
                self.text_ping_output.configure(state=ctk.NORMAL)
                self.text_ping_output.insert(
                    tk.END, "\nPing-Prozess abgeschlossen.\n", "myTag"
                )
                self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                self.text_ping_output.update_idletasks()
                self.text_ping_output.configure(state=ctk.DISABLED)
                current_process = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
            except Exception as e:
                print(e)
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
                self.text_ping_output.configure(state=ctk.NORMAL)
                self.text_ping_output.insert(
                    tk.END, "\nPing-Prozess wurde gestoppt.\n", "myTag"
                )
                self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                self.text_ping_output.update_idletasks()
                self.text_ping_output.configure(state=ctk.DISABLED)
                current_process = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
            except Exception as e:
                # Falls terminate() fehlschlägt, versuche kill()
                try:
                    current_process.kill()  # Erzwinge das Beenden des Prozesses
                    current_process.wait(
                        timeout=2
                    )  # Warte bis zu 2 Sekunden auf das Beenden
                    self.text_ping_output.configure(state=ctk.NORMAL)
                    self.text_ping_output.insert(
                        tk.END, "\nPing-Prozess wurde gestoppt.\n", "myTag"
                    )
                    self.text_ping_output.see(tk.END)  # Scrolle automatisch nach unten
                    self.text_ping_output.update_idletasks()
                    self.text_ping_output.configure(state=ctk.DISABLED)
                    current_process = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
                except Exception as e:
                    print(e)
                    messagebox.showerror(
                        "Fehler", f"Fehler beim Stoppen des Ping-Prozesses: {e}"
                    )
                    current_process = None

    def clear_ping_output(self):
        """Löscht die Ausgabe der Ping-Textbox."""
        self.text_ping_output.configure(state=ctk.NORMAL)
        self.text_ping_output.delete(1.0, ctk.END)
        self.text_ping_output.configure(state=ctk.DISABLED)

    def start_scan(self):
        target_ps = self.host_entry_ps.get().strip()
        try:
            start_port_ps = int(self.start_port_entry_ps.get().strip())
            end_port_ps = int(self.end_port_entry_ps.get().strip())
        except ValueError:
            self.table_ps.insert("", "end", values=("Fehler", "Ungültige Portnummer"))
            return

        for widget in self.action_frame_ps.winfo_children():
            widget.destroy()

        self.scanning_active_ps = True
        self.anim_rect_x_ps = 0
        self.anim_rect_direction_ps = 1

        self.anim_canvas_ps = tk.Canvas(
            self.action_frame_ps,
            width=self.canvas_width_ps,
            height=self.canvas_height_ps,
            # bg=self.tab_port_scan.cget("fg"),
            highlightthickness=0,
        )
        self.anim_canvas_ps.pack(pady=5)

        self.animate()

        threading.Thread(
            target=self.scan_ports,
            args=(target_ps, start_port_ps, end_port_ps),
            daemon=True,
        ).start()

    def animate(self):
        if not self.scanning_active_ps:
            return

        self.anim_canvas_ps.delete("all")
        self.anim_canvas_ps.create_rectangle(
            self.anim_rect_x_ps,
            5,
            self.anim_rect_x_ps + self.anim_rect_width_ps,
            5 + self.anim_rect_height_ps,
            fill="blue",
            outline="",
        )
        self.anim_rect_x_ps += self.anim_rect_direction_ps * 5

        if self.anim_rect_x_ps + self.anim_rect_width_ps >= self.canvas_width_ps:
            self.anim_rect_x_ps = self.canvas_width_ps - self.anim_rect_width_ps
            self.anim_rect_direction_ps = -1
        elif self.anim_rect_x_ps <= 0:
            self.anim_rect_x_ps = 0
            self.anim_rect_direction_ps = 1

        self.tab_port_scan.after(50, self.animate)

    def scan_ports(self, target_ps, start_port_ps, end_port_ps):
        self.open_ports_ps.clear()
        self.start_time_ps = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor_ps:
            future_to_port_ps = {
                executor_ps.submit(self.check_port, target_ps, port_ps): port_ps
                for port_ps in range(start_port_ps, end_port_ps + 1)
            }
            for future_ps in concurrent.futures.as_completed(future_to_port_ps):
                result_ps = future_ps.result()
                if result_ps is not None:
                    self.tab_port_scan.after(
                        0, lambda port_ps=result_ps: self.insert_port(port_ps)
                    )

        self.scanning_active_ps = False
        duration_ps = time.time() - self.start_time_ps
        self.tab_port_scan.after(0, lambda: self.finish_scan(duration_ps))

    def check_port(self, target_ps, port_ps):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_ps:
            s_ps.settimeout(0.5)
            return port_ps if s_ps.connect_ex((target_ps, port_ps)) == 0 else None

    def insert_port(self, new_port_ps):
        if new_port_ps not in self.open_ports_ps:
            self.open_ports_ps.append(new_port_ps)
            self.open_ports_ps.sort()

            for item in self.table_ps.get_children():
                self.table_ps.delete(item)

            for port_ps in self.open_ports_ps:
                self.table_ps.insert("", "end", values=(port_ps, "Offen"))

    def finish_scan(self, duration_ps):
        self.anim_canvas_ps.destroy()
        finished_label_ps = ctk.CTkLabel(
            self.action_frame_ps,
            text=f"Scan beendet in {duration_ps:.2f} Sekunden",
            fg_color="green",
        )
        finished_label_ps.pack(pady=5)
        self.tab_port_scan.after(
            3000, lambda: self.reset_action_frame(finished_label_ps)
        )

    def reset_action_frame(self, old_widget_ps):
        old_widget_ps.destroy()
        self.scan_button_ps = ctk.CTkButton(
            self.action_frame_ps, text="Scan", command=self.start_scan, corner_radius=20
        )
        self.scan_button_ps.pack(pady=5)

    ##############################################################
    # ping tab methods end
    ##############################################################

    ##############################################################
    # tracert tab methods start
    ##############################################################
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
                self.text_tracert_output.configure(state=ctk.NORMAL)
                self.text_tracert_output.insert(tk.END, line, "myTag2")
                self.text_tracert_output.see(tk.END)  # Scrolle automatisch nach unten
                self.text_tracert_output.update_idletasks()
                self.text_tracert_output.configure(state=ctk.DISABLED)

            current_process2.stdout.close()
            current_process2.wait()
            self.text_tracert_output.configure(state=ctk.NORMAL)
            self.text_tracert_output.insert(
                tk.END, "\nTracert-Prozess abgeschlossen.\n", "myTag2"
            )
            self.text_tracert_output.configure(state=ctk.DISABLED)
            current_process2 = (
                None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
            )
        except Exception as e:
            print(e)
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
                    self.text_tracert_output.configure(state=ctk.NORMAL)
                    self.text_tracert_output.insert(
                        tk.END, "\nTracert-Prozess wurde gestoppt.\n", "myTag2"
                    )
                    self.text_tracert_output.see(
                        tk.END
                    )  # Scrolle automatisch nach unten
                    self.text_tracert_output.update_idletasks()
                    self.text_tracert_output.configure(state=ctk.DISABLED)
                    global current_process2
                    current_process2 = None  # Setze den Prozess auf None, um einen neuen Start zu ermöglichen
                except Exception as e:
                    print(e)
                    messagebox.showerror(
                        "Fehler", f"Fehler beim Stoppen des Tracert-Prozesses: {e}"
                    )

                    current_process2 = None

            threading.Thread(target=terminate_process, args=(current_process2,)).start()

    def clear_tracert_output(self):
        """Löscht die Ausgabe der Tracert-Textbox."""
        self.text_tracert_output.configure(state=ctk.NORMAL)
        self.text_tracert_output.delete(1.0, ctk.END)
        self.text_tracert_output.configure(state=ctk.DISABLED)

    ##############################################################
    # tracert tab methods end
    ##############################################################

    ##############################################################
    # nslookup tab methods start
    ##############################################################

    def run_nslookup(self):
        domain = self.entry_nslookup_ip.get().strip()
        query_type = self.combobox_query_type.get()

        if not domain:
            print(e)
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

        self.text_nslookup_output.configure(state=ctk.NORMAL)
        self.text_nslookup_output.delete(1.0, ctk.END)

        self.text_nslookup_output.insert(1.0, "\n", "myTag3")
        self.text_nslookup_output.insert(tk.END, output, "myTag3")
        self.text_nslookup_output.configure(state=ctk.DISABLED)

    ##############################################################
    # -----------------nslookup tab methods end-----------------
    ##############################################################

    ##############################################################
    # -----------------speedtest tab methods start-----------------
    ##############################################################
    def start_speedtest(self):
        self.result_frame.pack_forget()
        # Reset der Tabelle und zeige Animation
        for row in range(1, 4):
            for col in range(2):
                self.labels[f"row{row}_col{col}"].configure(text="")

        self.start_button.configure(state="disabled")

        self.show_spinner()

        # Führe Speedtest in einem separaten Thread aus
        threading.Thread(target=self.run_speedtest).start()

    def run_speedtest(self):
        try:
            # Speedtest durchführen
            st = Speedtest(secure=True)
            # st.get_best_server()
            st.get_closest_servers()
            download_speed = st.download() / 1_000_000  # in Mbps
            upload_speed = st.upload() / 1_000_000  # in Mbps
            ping = st.results.ping  # Ping in ms

            # Ergebnisse in der Tabelle anzeigen
            results = [
                ["Download:", f"{download_speed:.2f} Mbit/s"],
                ["Upload:", f"{upload_speed:.2f} Mbit/s"],
                ["Ping:", f"{ping:.2f} ms"],
            ]
        except Exception as e:
            results = [["Fehler", str(e)]]

        # Zeige Ergebnisse in der Tabelle
        self.root.after(0, self.show_results, results)

    def show_spinner(self):
        self.animating = True  # Animation aktiv
        self.canvas.pack(pady=20, side="top")
        self.double_ring10()

    def double_ring10(self):
        # Setze die Startwinkel und starte die Animation
        self.dr10_angle1 = 0
        self.dr10_angle2 = 0
        self.dr10_angle3 = 0
        self.dr10()

    def dr10(self):
        # Prüfe, ob die Animation noch laufen soll
        if not self.animating:
            return

        self.canvas.delete("all")
        # (Optional: Das erneute Packen kann entfallen, wenn das Canvas bereits sichtbar ist)
        self.canvas.pack(pady=20, side="top")
        cx, cy = 150, 150
        radius1 = 60
        radius2 = 45
        radius3 = 30
        self.canvas.create_arc(
            cx - radius1,
            cy - radius1,
            cx + radius1,
            cy + radius1,
            start=self.dr10_angle1,
            extent=90,
            style=tk.ARC,
            outline="blue",
            width=5,
        )
        self.canvas.create_arc(
            cx - radius2,
            cy - radius2,
            cx + radius2,
            cy + radius2,
            start=self.dr10_angle2,
            extent=90,
            style=tk.ARC,
            outline="red",
            width=5,
        )
        self.canvas.create_arc(
            cx - radius3,
            cy - radius3,
            cx + radius3,
            cy + radius3,
            start=self.dr10_angle3,
            extent=90,
            style=tk.ARC,
            outline="green",
            width=5,
        )
        # Aktualisiere Winkel
        self.dr10_angle1 = (self.dr10_angle1 + 3) % 360
        self.dr10_angle2 = (self.dr10_angle2 + 6) % 360
        self.dr10_angle3 = (self.dr10_angle3 + 9) % 360
        # Plane den nächsten Animationsschritt, wenn noch animiert werden soll
        self.animation_job = self.root.after(40, self.dr10)

    def stop_animation(self):
        """Beendet die Animation."""
        self.animating = False  # Flag deaktivieren
        if self.animation_job:
            self.root.after_cancel(self.animation_job)
            self.animation_job = None
        self.canvas.delete("all")
        self.canvas.pack_forget()

    def show_results(self, results):
        self.result_frame.pack(pady=40, padx=40)
        # Stoppe Animation und zeige Ergebnisse
        self.stop_animation()  # Animation beenden
        self.start_button.configure(state="normal")
        # Aktualisiere die Tabelle mit den Ergebnissen
        for row, (param, value) in enumerate(results, start=1):
            self.labels[f"row{row}_col0"].configure(text=param)
            self.labels[f"row{row}_col1"].configure(text=value)

    ##############################################################
    # -----------------speedtest tab methods end-----------------
    ##############################################################
    ##############################################################
    # -----------------porttest tab methods start----------------
    ##############################################################

    def test_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                return result == 0
        except Exception as e:
            print(f"Fehler bei der Portprüfung: {e}")
            return False

    def check_ports(self):
        ip = self.entry_ip_address.get()
        if not ip:
            messagebox.showwarning("Warnung", "Bitte eine gültige IP-Adresse eingeben.")
            return

        additional_ports = self.entry_additional_ports.get().split()
        for port_str in additional_ports:
            try:
                port = int(port_str)
                is_open = self.test_port(ip, port)
                self.update_status(str(port), is_open)
            except ValueError:
                print(f"Ungültiger Port: {port_str}")

        if self.checking:
            self.timer_id = self.root.after(5000, self.check_ports)

    def update_status(self, port_name, is_open):
        color = "green" if is_open else "red"
        text = "Offen" if is_open else "Geschlossen"

        for child in self.tree.get_children():
            if self.tree.item(child, "values")[0] == port_name:
                self.tree.item(child, values=(port_name, text), tags=(color,))
                return

        self.tree.insert("", "end", values=(port_name, text), tags=(color,))
        self.update_table_height()

    def update_table_height(self):
        num_ports = len(self.entry_additional_ports.get().split())
        self.tree.configure(height=max(num_ports, 1))

    def start_checking(self):
        if not self.checking:
            self.chk_port_443.configure(state=ctk.DISABLED)
            self.chk_port_8802.configure(state=ctk.DISABLED)
            self.checking = True
            self.check_ports()
            self.btn_check.configure(text="Stoppen")
            self.btn_clear_ports.configure(state=ctk.DISABLED)
        else:
            self.chk_port_443.configure(state=ctk.NORMAL)
            self.chk_port_8802.configure(state=ctk.NORMAL)
            self.checking = False
            self.btn_check.configure(text="Check Starten")
            self.btn_clear_ports.configure(state=ctk.NORMAL)

            if self.timer_id is not None:
                self.root.after_cancel(self.timer_id)
                self.timer_id = None

            for child in self.tree.get_children():
                self.tree.delete(child)

    def toggle_port_in_entry(self, port, var):
        current_ports = self.entry_additional_ports.get().split()
        port_str = str(port)

        if var.get():
            if port_str not in current_ports:
                current_ports.append(port_str)
        else:
            if port_str in current_ports:
                current_ports.remove(port_str)

        self.entry_additional_ports.delete(0, ctk.END)
        self.entry_additional_ports.insert(0, " ".join(current_ports))
        self.validate_input()
        self.update_table_height()

    def validate_input(self):
        ip = self.entry_ip_address.get()
        ports = self.entry_additional_ports.get().strip()
        self.btn_check.configure(state=ctk.NORMAL if ip and ports else tk.DISABLED)

    def clear_ports(self):
        self.entry_additional_ports.delete(0, ctk.END)
        self.validate_input()
        self.update_table_height()
        self.var_port_443.set(False)
        self.var_port_8802.set(False)

    ##############################################################
    # -----------------porttest tab methods end------------------
    ##############################################################
    ##############################################################
    # -----------------ip-scan tab methods start------------------
    ##############################################################

    def get_network_interfaces_ipsc(self):
        """Ermittelt die verfügbaren Netzwerkkarten mit wmi."""
        try:
            c = wmi.WMI()
            self.interfaces_ipsc = {
                "Bitte Netzwerkkarte auswählen": {
                    "ip": "",
                    "subnet": "",
                    "gateway": "",
                    "dns": "",
                    "dhcp": "",
                }
            }
            interfaces_names = ["Bitte Netzwerkkarte auswählen"]

            for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                interface_name = nic.Description
                interfaces_names.append(interface_name)
                ip_address = nic.IPAddress[0] if nic.IPAddress else ""
                subnet_mask = nic.IPSubnet[0] if nic.IPSubnet else ""
                gateway = nic.DefaultIPGateway[0] if nic.DefaultIPGateway else ""
                dns_servers = (
                    ", ".join(nic.DNSServerSearchOrder)
                    if nic.DNSServerSearchOrder
                    else ""
                )
                dhcp_enabled = nic.DHCPEnabled

                self.interfaces_ipsc[interface_name] = {
                    "ip": ip_address,
                    "subnet": subnet_mask,
                    "gateway": gateway,
                    "dns": dns_servers,
                    "dhcp": dhcp_enabled,
                }

            return interfaces_names
        except Exception as e:
            print(f"Fehler beim Ermitteln der Netzwerkkarten: {e}")
            return {}

    def get_ip_info_ipsc(self, interface_ipsc):
        """Ermittelt die IP-Adresse und das Netzwerk der ausgewählten Netzwerkkarte."""
        akt_ipadr = self.interfaces_ipsc[interface_ipsc]["ip"]
        ersteIP, letzteIP = self.generate_ip_range_ipsc(
            akt_ipadr, self.interfaces_ipsc[interface_ipsc]["subnet"]
        )

        self.start_ip_entry_ipsc.delete(0, ctk.END)
        self.start_ip_entry_ipsc.insert(0, ersteIP)
        self.end_ip_entry_ipsc.delete(0, ctk.END)
        self.end_ip_entry_ipsc.insert(0, letzteIP)

        return None, None

    def generate_ip_range_ipsc(self, ip, subnet_mask):
        """
        Berechnet die erste und letzte nutzbare IP-Adresse in einem Subnetz,
        basierend auf einer gegebenen IP-Adresse (egal ob es die Netzwerkadresse ist oder nicht)
        und der zugehörigen Subnetzmaske.

        :param ip: Eine IP-Adresse im Subnetz (z. B. "192.168.1.100")
        :param subnet_mask: Die Subnetzmaske (z. B. "255.255.255.0")
        :return: Ein Tupel (erste_nutzbare_IP, letzte_nutzbare_IP) als Strings.
        """
        # Erstelle das Netzwerk-Objekt, auch wenn die übergebene IP-Adresse nicht
        # die exakte Netzwerkadresse ist.
        network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)

        # Erstelle eine Liste aller nutzbaren Hostadressen (ohne Netzwerk- und Broadcast-Adresse)
        hosts = list(network.hosts())

        if hosts:
            first_usable = hosts[0]
            last_usable = hosts[-1]
            return str(first_usable), str(last_usable)
        else:
            # Falls es keine nutzbaren Hosts gibt (z.B. in einem /32-Netz)
            return None, None

    def get_hostname_ipsc(self, ip_ipsc):
        try:
            return socket.gethostbyaddr(ip_ipsc)[0]
        except socket.herror:
            return "Unbekannt"

    def get_mac_vendor_ipsc(self, mac_ipsc):

        try:
            response = requests.get(
                f"https://www.macvendorlookup.com/api/v2/{mac_ipsc}", timeout=10
            )
            if response.status_code == 200:
                # print("-")
                # print(response.json()[0]["company"])
                # print("-")

                return response.json()[0]["company"]

            else:
                try:
                    response = requests.get(
                        f"https://api.macvendors.com/{mac_ipsc}", timeout=10
                    )
                    if response.status_code == 200:
                        if response.text == "":
                            return "Unbekannt"
                        return response.text
                    else:
                        return "Unbekannt"
                except Exception:
                    return "Unbekannt"
        except Exception:
            return "Unbekannt"

    def scan_single_ip_ipsc(self, interface_ipsc, ip_address_ipsc):
        if self.stop_scan_flag_ipsc:
            return None
        ans, _ = scapy.arping(
            ip_address_ipsc, iface=interface_ipsc, timeout=1, verbose=False
        )
        for snd, rcv in ans:
            mac = rcv.hwsrc
            return {
                "Name": self.get_hostname_ipsc(rcv.psrc),
                "IP": rcv.psrc,
                "MAC": mac,
                "Hersteller": self.get_mac_vendor_ipsc(mac),
            }
        return None

    def scan_ip_range_ipsc(self, interface_ipsc, start_ip_ipsc, end_ip_ipsc):
        start = int(start_ip_ipsc.split(".")[-1])
        end = int(end_ip_ipsc.split(".")[-1])

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            self.executor_ipsc = executor
            futures = [
                executor.submit(
                    self.scan_single_ip_ipsc,
                    interface_ipsc,
                    f"{start_ip_ipsc.rsplit('.', 1)[0]}.{i}",
                )
                for i in range(start, end + 1)
            ]
            for future in concurrent.futures.as_completed(futures):
                if self.stop_scan_flag_ipsc:
                    executor.shutdown(wait=False)
                    break
                device = future.result()
                if device:
                    self.scan_results_ipsc.append(device)
                    self.tab_ip_scan.after(0, self.update_treeview_ipsc)

        if not self.stop_scan_flag_ipsc:
            self.tab_ip_scan.after(
                0,
                lambda: messagebox.showinfo(
                    "Scan abgeschlossen",
                    f"Gefundene IPs: {len(self.scan_results_ipsc)}\nDauer: {round(time.time() - self.start_time_ipsc, 2)} Sek.",
                ),
            )
        self.tab_ip_scan.after(
            0, lambda: self.scan_button_ipsc.configure(state=ctk.NORMAL)
        )
        self.tab_ip_scan.after(
            0, lambda: self.stop_button_ipsc.configure(state=ctk.DISABLED)
        )

    def start_scan_ipsc(self):
        self.stop_scan_flag_ipsc = False

        interface_ipsc = self.interface_combobox_ipsc.get()
        if not interface_ipsc:
            return
        for item in self.tree_ipsc.get_children():
            self.tree_ipsc.delete(item)

        self.scan_button_ipsc.configure(state=ctk.DISABLED)
        self.stop_button_ipsc.configure(state=ctk.NORMAL)
        self.start_time_ipsc = time.time()
        thread = threading.Thread(
            target=self.perform_scan_ipsc,
            args=(
                interface_ipsc,
                self.start_ip_entry_ipsc.get(),
                self.end_ip_entry_ipsc.get(),
            ),
            daemon=True,
        )
        thread.start()

    def stop_scan_ipsc(self):
        self.stop_scan_flag_ipsc = True
        if self.executor_ipsc:
            self.executor_ipsc.shutdown(wait=False)
        self.scan_button_ipsc.configure(state=ctk.NORMAL)
        self.stop_button_ipsc.configure(state=ctk.DISABLED)

    def perform_scan_ipsc(self, interface_ipsc, start_ip_ipsc, end_ip_ipsc):
        self.scan_ip_range_ipsc(interface_ipsc, start_ip_ipsc, end_ip_ipsc)

    def update_ip_range_ipsc(self, *args):

        interface_ipsc = self.interface_combobox_ipsc.get()
        if interface_ipsc == "Bitte Netzwerkkarte auswählen":
            self.scan_button_ipsc.configure(state=ctk.DISABLED)
            self.stop_button_ipsc.configure(state=ctk.DISABLED)
            self.start_ip_entry_ipsc.delete(0, ctk.END)
            self.end_ip_entry_ipsc.delete(0, ctk.END)
            return
        else:
            self.scan_button_ipsc.configure(state=ctk.NORMAL)
            self.stop_button_ipsc.configure(state=ctk.DISABLED)

        ip_address_ipsc, network_ipsc = self.get_ip_info_ipsc(interface_ipsc)
        if network_ipsc:
            start_ip_ipsc, end_ip_ipsc = self.generate_ip_range_ipsc(network_ipsc)
            self.start_ip_entry_ipsc.delete(0, ctk.END)
            self.start_ip_entry_ipsc.insert(0, start_ip_ipsc)
            self.end_ip_entry_ipsc.delete(0, ctk.END)
            self.end_ip_entry_ipsc.insert(0, end_ip_ipsc)

    def sort_treeview_ipsc(self, col_ipsc, reverse=False):
        data = [
            (self.tree_ipsc.set(item, col_ipsc), item)
            for item in self.tree_ipsc.get_children("")
        ]
        if col_ipsc == "IP":
            data.sort(key=lambda x: tuple(map(int, x[0].split("."))), reverse=reverse)
        else:
            data.sort(reverse=reverse)
        for index, (_, item) in enumerate(data):
            self.tree_ipsc.move(item, "", index)
        self.tree_ipsc.heading(
            col_ipsc, command=lambda: self.sort_treeview_ipsc(col_ipsc, not reverse)
        )

    def open_http_ipsc(self):
        selected_item = self.tree_ipsc.selection()
        if selected_item:
            ip = self.tree_ipsc.item(selected_item[0], "values")[1]
            webbrowser.open(f"http://{ip}")

    def open_https_ipsc(self):
        selected_item = self.tree_ipsc.selection()
        if selected_item:
            ip = self.tree_ipsc.item(selected_item[0], "values")[1]
            webbrowser.open(f"https://{ip}")

    def show_context_menu_ipsc(self, event):
        selected_item = self.tree_ipsc.identify_row(event.y)
        if selected_item:
            self.tree_ipsc.selection_set(selected_item)
            self.context_menu_ipsc.post(event.x_root, event.y_root)

    def filter_results_ipsc(self):
        self.filter_text_ipsc = self.filter_entry_ipsc.get().lower()
        self.update_treeview_ipsc()

    def update_treeview_ipsc(self):
        for item in self.tree_ipsc.get_children():
            self.tree_ipsc.delete(item)
        if not self.scan_results_ipsc:
            return
        for device in self.scan_results_ipsc:

            if self.filter_entry_ipsc.get() == "" or any(
                self.filter_entry_ipsc.get() in str(value).lower()
                for value in device.values()
            ):
                self.tree_ipsc.insert(
                    "",
                    "end",
                    values=(
                        device["Name"],
                        device["IP"],
                        device["MAC"],
                        device["Hersteller"],
                    ),
                )

    def export_to_pdf_ipsc(self):
        if not self.scan_results_ipsc:
            messagebox.showwarning(
                "Keine Daten", "Es gibt keine Scan-Ergebnisse zum Exportieren."
            )
            return

        # Ordnerauswahl
        folder_path = filedialog.askdirectory()
        if not folder_path:
            return

        # PDF erstellen
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=30)
        pdf.cell(200, 10, txt="IP-Scan-Ergebnisse", ln=True, align="C")
        pdf.ln(10)

        # Tabelle erstellen
        pdf.set_font("Arial", size=16)
        col_widths = [65, 30, 30, 65]
        headers = ["Name", "IP", "MAC", "Hersteller"]
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 10, txt=header, border=1, align="C")
        pdf.ln()
        pdf.set_font("Arial", size=8)

        for device in self.scan_results_ipsc:
            for i, key in enumerate(["Name", "IP", "MAC", "Hersteller"]):
                pdf.cell(col_widths[i], 6, txt=str(device[key]), border=1, align="C")
            pdf.ln()

        # PDF speichern
        pdf_path = f"{folder_path}/scan_ergebnisse.pdf"
        pdf.output(pdf_path)
        messagebox.showinfo(
            "PDF exportiert",
            f"Die Scan-Ergebnisse wurden erfolgreich nach {pdf_path} exportiert.",
        )
        webbrowser.open(pdf_path)

    # -----------------ip-scan tab methods end------------------


if __name__ == "__main__":
    try:
        # Überprüfen, ob das Programm mit Administratorrechten ausgeführt wird
        if not is_admin():
            # Programm neu starten mit Administratorrechten
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        else:
            setup_logger()
            print("Adminrechte i.O.")
            root = ctk.CTk()
            # ctk.set_appearance_mode("dark")
            ctk.set_appearance_mode("light")
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

        type, value, traceback = sys.exc_info()
        print(f"Type: {type}")
        print(f"Value: {value}")
        print(f"Traceback: {traceback}")
        time.sleep(5)
        sys.exit(1)
