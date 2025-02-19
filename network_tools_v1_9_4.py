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

            # Globale Variablen

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

            self.tcp_ports = {
                0: "Reserved",
                1: "Port Service Multiplexer",
                2: "Management Utility",
                3: "Compression Process",
                4: "Unassigned",
                5: "Remote Job Entry",
                6: "Unassigned",
                7: "Echo",
                8: "Unassigned",
                9: "Discard",
                10: "Unassigned",
                11: "Active Users",
                12: "Unassigned",
                13: "Daytime (RFC 867)",
                14: "Unassigned",
                15: "Unassigned [was netstat]",
                16: "Unassigned",
                17: "Quote of the Day",
                18: "Message Send Protocol",
                19: "Character Generator",
                20: "File Transfer [Default Data]",
                21: "File Transfer [Control]",
                22: "SSH Remote Login Protocol",
                23: "Telnet",
                24: "any private mail system",
                25: "Simple Mail Transfer",
                26: "Unassigned",
                27: "NSW User System FE",
                28: "Unassigned",
                29: "MSG ICP",
                30: "Unassigned",
                31: "MSG Authentication",
                32: "Unassigned",
                33: "Display Support Protocol",
                34: "Unassigned",
                35: "any private printer server",
                36: "Unassigned",
                37: "Time / W32.Sober.I virus",
                38: "Route Access Protocol",
                39: "Resource Location Protocol",
                40: "Unassigned",
                41: "Graphics",
                42: "Host Name Server",
                43: "WhoIs",
                44: "MPM FLAGS Protocol",
                45: "Message Processing Module [recv]",
                46: "MPM [default send]",
                47: "NI FTP",
                48: "Digital Audit Daemon",
                49: "Login Host Protocol (TACACS)",
                50: "Remote Mail Checking Protocol",
                51: "IMP Logical Address Maintenance",
                52: "XNS Time Protocol",
                53: "Domain Name Server",
                54: "XNS Clearinghouse",
                55: "ISI Graphics Language",
                56: "XNS Authentication",
                57: "any private terminal access",
                58: "XNS Mail",
                59: "any private file service",
                60: "Unassigned",
                61: "NI MAIL",
                62: "ACA Services",
                63: "whois++",
                64: "Communications Integrator (CI)",
                65: "TACACS-Database Service",
                66: "Oracle SQL*NET",
                67: "Bootstrap Protocol Server",
                68: "Bootstrap Protocol Client",
                69: "Trivial File Transfer",
                70: "Gopher",
                71: "Remote Job Service",
                72: "Remote Job Service",
                73: "Remote Job Service",
                74: "Remote Job Service",
                75: "any private dial out service",
                76: "Distributed External Object Store",
                77: "any private RJE service",
                78: "vettcp",
                79: "Finger",
                80: "World Wide Web HTTP",
                81: "HOSTS2 Name Server / Bagle-AZ worm / Win32.Rbot worm",
                82: "XFER Utility",
                83: "MIT ML Device",
                84: "Common Trace Facility",
                85: "MIT ML Device",
                86: "Micro Focus Cobol",
                87: "any private terminal link",
                88: "Kerberos",
                89: "SU/MIT Telnet Gateway",
                90: "DNSIX Securit Attribute Token Map",
                91: "MIT Dover Spooler",
                92: "Network Printing Protocol",
                93: "Device Control Protocol",
                94: "Tivoli Object Dispatcher",
                95: "SUPDUP",
                96: "DIXIE Protocol Specification",
                97: "Swift Remote Virtural File Protocol",
                98: "Linuxconf / TAC News",
                99: "Metagram Relay",
                100: "[unauthorized use]",
                101: "NIC Host Name Server",
                102: "MSExchangeMTA X.400 / ISO-TSAP Class 0",
                103: "Genesis Point-to-Point Trans Net",
                104: "ACR-NEMA Digital Imag. & Comm. 300",
                105: "Mailbox Name Nameserver",
                106: "3COM-TSMUX",
                107: "Remote Telnet Service",
                108: "SNA Gateway Access Server",
                109: "Post Office Protocol - Version 2",
                110: "Post Office Protocol - Version 3",
                111: "SUN Remote Procedure Call",
                112: "McIDAS Data Transmission Protocol",
                113: "Authentication Service",
                114: "Audio News Multicast",
                115: "Simple File Transfer Protocol",
                116: "ANSA REX Notify",
                117: "UUCP Path Service",
                118: "SQL Services",
                119: "Network News Transfer Protocol",
                120: "CFDPTKT",
                121: "Encore Expedited Remote Pro.Call",
                122: "SMAKYNET",
                123: "Network Time Protocol",
                124: "ANSA REX Trader",
                125: "Locus PC-Interface Net Map Ser",
                126: "Unisys Unitary Login",
                127: "Locus PC-Interface Conn Server",
                128: "GSS X License Verification",
                129: "Password Generator Protocol",
                130: "cisco FNATIVE",
                131: "cisco TNATIVE",
                132: "cisco SYSMAINT",
                133: "Statistics Service",
                134: "INGRES-NET Service",
                135: "DCE endpoint resolution",
                136: "PROFILE Naming System",
                137: "NETBIOS Name Service",
                138: "NETBIOS Datagram Service",
                139: "NETBIOS Session Service",
                140: "EMFIS Data Service",
                141: "EMFIS Control Service",
                142: "Britton-Lee IDM",
                143: "Internet Message Access Protocol",
                144: "Universal Management Architecture",
                145: "UAAC Protocol",
                146: "ISO-IP0",
                147: "ISO-IP",
                148: "Jargon",
                149: "AED 512 Emulation Service",
                150: "SQL-NET",
                151: "HEMS",
                152: "Background File Transfer Program",
                153: "SGMP",
                154: "NETSC",
                155: "NETSC",
                156: "SQL Service",
                157: "KNET/VM Command/Message Protocol",
                158: "PCMail Server",
                159: "NSS-Routing",
                160: "SGMP-TRAPS",
                161: "SNMP",
                162: "SNMPTRAP",
                163: "CMIP/TCP Manager",
                164: "CMIP/TCP Agent",
                165: "Xerox",
                166: "Sirius Systems",
                167: "NAMP",
                168: "RSVD",
                169: "SEND",
                170: "Network PostScript",
                171: "Network Innovations Multiplex",
                172: "Network Innovations CL/1",
                173: "Xyplex",
                174: "MAILQ",
                175: "VMNET",
                176: "GENRAD-MUX",
                177: "X Display Manager Control Protocol",
                178: "NextStep Window Server",
                179: "Border Gateway Protocol",
                180: "Intergraph",
                181: "Unify",
                182: "Unisys Audit SITP",
                183: "OCBinder",
                184: "OCServer",
                185: "Remote-KIS",
                186: "KIS Protocol",
                187: "Application Communication Interface",
                188: "Plus Five's MUMPS",
                189: "Queued File Transport",
                190: "Gateway Access Control Protocol",
                191: "Prospero Directory Service",
                192: "OSU Network Monitoring System",
                193: "Spider Remote Monitoring Protocol",
                194: "Internet Relay Chat Protocol",
                195: "DNSIX Network Level Module Audit",
                196: "DNSIX Session Mgt Module Audit Redir",
                197: "Directory Location Service",
                198: "Directory Location Service Monitor",
                199: "SMUX",
                200: "IBM System Resource Controller",
                201: "AppleTalk Routing Maintenance",
                202: "AppleTalk Name Binding",
                203: "AppleTalk Unused",
                204: "AppleTalk Echo",
                205: "AppleTalk Unused",
                206: "AppleTalk Zone Information",
                207: "AppleTalk Unused",
                208: "AppleTalk Unused",
                209: "The Quick Mail Transfer Protocol",
                210: "ANSI Z39.50",
                211: "Texas Instruments 914C/G Terminal",
                212: "ATEXSSTR",
                213: "IPX",
                214: "VM PWSCS",
                215: "Insignia Solutions",
                216: "Computer Associates Int'l License Server",
                217: "dBASE Unix",
                218: "Netix Message Posting Protocol",
                219: "Unisys ARPs",
                220: "Interactive Mail Access Protocol v3",
                221: "Berkeley rlogind with SPX auth",
                222: "Berkeley rshd with SPX auth",
                223: "Certificate Distribution Center",
                224: "masqdialer",
                242: "Direct",
                243: "Survey Measurement",
                244: "inbusiness",
                245: "LINK",
                246: "Display Systems Protocol",
                247: "SUBNTBCST_TFTP",
                248: "bhfhs",
                256: "RAP/Checkpoint SNMP",
                257: "Check Point / Secure Electronic Transaction",
                258: "Check Point / Yak Winsock Personal Chat",
                259: "Check Point Firewall-1 telnet auth / Efficient Short Remote Operations",
                260: "Openport",
                261: "IIOP Name Service over TLS/SSL",
                262: "Arcisdms",
                263: "HDAP",
                264: "BGMP / Check Point",
                265: "X-Bone CTL",
                266: "SCSI on ST",
                267: "Tobit David Service Layer",
                268: "Tobit David Replica",
                280: "HTTP-mgmt",
                281: "Personal Link",
                282: "Cable Port A/X",
                283: "rescap",
                284: "corerjd",
                286: "FXP-1",
                287: "K-BLOCK",
                308: "Novastor Backup",
                309: "EntrustTime",
                310: "bhmds",
                311: "AppleShare IP WebAdmin",
                312: "VSLMP",
                313: "Magenta Logic",
                314: "Opalis Robot",
                315: "DPSI",
                316: "decAuth",
                317: "Zannet",
                318: "PKIX TimeStamp",
                319: "PTP Event",
                320: "PTP General",
                321: "PIP",
                322: "RTSPS",
                333: "Texar Security Port",
                344: "Prospero Data Access Protocol",
                345: "Perf Analysis Workbench",
                346: "Zebra server",
                347: "Fatmen Server",
                348: "Cabletron Management Protocol",
                349: "mftp",
                350: "MATIP Type A",
                351: "bhoetty (added 5/21/97)",
                352: "bhoedap4 (added 5/21/97)",
                353: "NDSAUTH",
                354: "bh611",
                355: "DATEX-ASN",
                356: "Cloanto Net 1",
                357: "bhevent",
                358: "Shrinkwrap",
                359: "Tenebris Network Trace Service",
                360: "scoi2odialog",
                361: "Semantix",
                362: "SRS Send",
                363: "RSVP Tunnel",
                364: "Aurora CMGR",
                365: "DTK",
                366: "ODMR",
                367: "MortgageWare",
                368: "QbikGDP",
                369: "rpc2portmap",
                370: "codaauth2",
                371: "Clearcase",
                372: "ListProcessor",
                373: "Legent Corporation",
                374: "Legent Corporation",
                375: "Hassle",
                376: "Amiga Envoy Network Inquiry Proto",
                377: "NEC Corporation",
                378: "NEC Corporation",
                379: "TIA/EIA/IS-99 modem client",
                380: "TIA/EIA/IS-99 modem server",
                381: "hp performance data collector",
                382: "hp performance data managed node",
                383: "hp performance data alarm manager",
                384: "A Remote Network Server System",
                385: "IBM Application",
                386: "ASA Message Router Object Def.",
                387: "Appletalk Update-Based Routing Pro.",
                388: "Unidata LDM",
                389: "Lightweight Directory Access Protocol / Internet Locator Service (ILS)",
                390: "UIS",
                391: "SynOptics SNMP Relay Port",
                392: "SynOptics Port Broker Port",
                393: "Data Interpretation System",
                394: "EMBL Nucleic Data Transfer",
                395: "NETscout Control Protocol",
                396: "Novell Netware over IP",
                397: "Multi Protocol Trans. Net.",
                398: "Kryptolan",
                399: "ISO Transport Class 2 Non-Control over TCP",
                400: "Workstation Solutions",
                401: "Uninterruptible Power Supply",
                402: "Genie Protocol",
                403: "decap",
                404: "nced",
                405: "ncld",
                406: "Interactive Mail Support Protocol",
                407: "Timbuktu",
                408: "Prospero Resource Manager Sys. Man.",
                409: "Prospero Resource Manager Node Man.",
                410: "DECLadebug Remote Debug Protocol",
                411: "Remote MT Protocol",
                412: "NeoModus Direct Connect (Windows file sharing program) / Trap Convention Port",
                413: "SMSP",
                414: "InfoSeek",
                415: "BNet",
                416: "Silverplatter",
                417: "Onmux",
                418: "Hyper-G",
                419: "Ariel",
                420: "SMPTE",
                421: "Ariel",
                422: "Ariel",
                423: "IBM Operations Planning and Control Start",
                424: "IBM Operations Planning and Control Track",
                425: "ICAD",
                426: "smartsdp",
                427: "Server Location",
                428: "OCS_CMU",
                429: "OCS_AMU",
                430: "UTMPSD",
                431: "UTMPCD",
                432: "IASD",
                433: "NNSP",
                434: "MobileIP-Agent",
                435: "MobilIP-MN",
                436: "DNA-CML",
                437: "comscm",
                438: "dsfgw",
                439: "dasp",
                440: "sgcp",
                441: "decvms-sysmgt",
                442: "cvc_hostd",
                443: "HTTP protocol over TLS/SSL",
                444: "Simple Network Paging Protocol",
                445: "Microsoft-DS",
                446: "DDM-RDB",
                447: "DDM-RFM",
                448: "DDM-SSL",
                449: "AS Server Mapper",
                450: "TServer",
                451: "Cray Network Semaphore server",
                452: "Cray SFS config server",
                453: "CreativeServer",
                454: "ContentServer",
                455: "CreativePartnr",
                456: "macon-tcp",
                457: "scohelp",
                458: "apple quick time",
                459: "ampr-rcmd",
                460: "skronk",
                461: "DataRampSrv",
                462: "DataRampSrvSec",
                463: "alpes",
                464: "kpasswd",
                465: "SMTPS",
                466: "digital-vrc",
                467: "mylex-mapd",
                468: "proturis",
                469: "Radio Control Protocol",
                470: "scx-proxy",
                471: "Mondex",
                472: "ljk-login",
                473: "hybrid-pop",
                474: "tn-tl-w1",
                475: "tcpnethaspsrv",
                476: "tn-tl-fd1",
                477: "ss7ns",
                478: "spsc",
                479: "iafserver",
                480: "iafdbase",
                481: "Ph service",
                482: "bgs-nsi",
                483: "ulpnet",
                484: "Integra Software Management Environment",
                485: "Air Soft Power Burst",
                486: "avian",
                487: "saft Simple Asynchronous File Transfer",
                488: "gss-HTTP",
                489: "nest-protocol",
                490: "micom-pfs",
                491: "go-login",
                492: "Transport Independent Convergence for FNA",
                493: "Transport Independent Convergence for FNA",
                494: "POV-Ray",
                495: "intecourier",
                496: "PIM-RP-DISC",
                497: "dantz",
                498: "siam",
                499: "ISO ILL Protocol",
                500: "ISAKMP",
                501: "STMF",
                502: "asa-appl-proto",
                503: "Intrinsa",
                504: "citadel",
                505: "mailbox-lm",
                506: "ohimsrv",
                507: "crs",
                508: "xvttp",
                509: "snare",
                510: "FirstClass Protocol",
                511: "PassGo",
                512: "Remote process execution",
                513: "Remote Login",
                514: "Remote Shell",
                515: "spooler",
                516: "videotex",
                517: "like tenex link but across",
                518: "talkd",
                519: "unixtime",
                520: "extended file name server",
                521: "ripng",
                522: "User Location Service / ULP",
                523: "IBM-DB2",
                524: "NCP",
                525: "timeserver",
                526: "newdate",
                527: "Stock IXChange",
                528: "Customer IXChange",
                529: "IRC-SERV",
                530: "rpc",
                531: "chat",
                532: "readnews",
                533: "for emergency broadcasts",
                534: "MegaMedia Admin",
                535: "iiop",
                536: "opalis-rdv",
                537: "Networked Media Streaming Protocol",
                538: "gdomap",
                539: "Apertus Technologies Load Determination",
                540: "uucpd",
                541: "uucp-rlogin",
                542: "commerce",
                543: "kerberos (v4/v5)",
                544: "krcmd",
                545: "appleqtcsrvr",
                546: "DHCPv6 Client",
                547: "DHCPv6 Server",
                548: "AppleShare AFP over TCP",
                549: "IDFP",
                550: "new-who",
                551: "cybercash",
                552: "deviceshare",
                553: "pirp",
                554: "Real Time Stream Control Protocol",
                555: "phAse Zero backdoor (Win 9x, NT) / dsf",
                556: "rfs server",
                557: "openvms-sysipc",
                558: "SDNSKMP",
                559: "TEEDTAP / Backdoor.Domwis Win32 trojan",
                560: "rmonitord",
                561: "monitor",
                562: "chcmd",
                563: "AOL IM / NNTP protocol over TLS/SSL",
                564: "plan 9 file service",
                565: "whoami",
                566: "streettalk",
                567: "banyan-rpc",
                568: "microsoft shuttle",
                569: "microsoft rome",
                570: "demon",
                571: "udemon",
                572: "sonar",
                573: "banyan-vip",
                574: "FTP Software Agent System",
                575: "VEMMI",
                576: "ipcd",
                577: "vnas",
                578: "ipdd",
                579: "decbsrv",
                580: "SNTP HEARTBEAT",
                581: "Bundle Discovery Protocol",
                582: "SCC Security",
                583: "Philips Video-Conferencing",
                584: "Key Server",
                585: "IMAP4+SSL",
                586: "Password Change",
                587: "Message Submission (Sendmail)",
                588: "CAL",
                589: "EyeLink",
                590: "TNS CML",
                591: "FileMaker Inc. - HTTP Alternate",
                592: "Eudora Set",
                593: "HTTP RPC Ep Map",
                594: "TPIP",
                595: "CAB Protocol",
                596: "SMSD",
                597: "PTC Name Service",
                598: "SCO Web Server Manager 3",
                599: "Aeolon Core Protocol",
                600: "Sun IPC server",
                606: "Cray Unified Resource Manager",
                607: "nqs",
                608: "Sender-Initiated/Unsolicited File Transfer",
                609: "npmp-trap",
                610: "Apple Admin Service / npmp-local",
                611: "npmp-gui",
                612: "HMMP Indication",
                613: "HMMP Operation",
                614: "SSLshell",
                615: "Internet Configuration Manager",
                616: "SCO System Administration Server",
                617: "SCO Desktop Administration Server",
                618: "DEI-ICDA",
                619: "Digital EVM",
                620: "SCO WebServer Manager",
                621: "ESCP",
                622: "Collaborator",
                623: "Aux Bus Shunt",
                624: "Crypto Admin",
                625: "DEC DLM",
                626: "ASIA",
                627: "PassGo Tivoli",
                628: "QMQP",
                629: "3Com AMP3",
                630: "RDA",
                631: "IPP (Internet Printing Protocol)",
                632: "bmpp",
                633: "Service Status update (Sterling Software)",
                634: "ginad",
                635: "RLZ DBase",
                636: "LDAP protocol over TLS/SSL",
                637: "lanserver",
                638: "mcns-sec",
                639: "MSDP",
                640: "entrust-sps",
                641: "repcmd",
                642: "ESRO-EMSDP V1.3",
                643: "SANity",
                644: "dwr",
                645: "PSSC",
                646: "LDP",
                647: "DHCP Failover",
                648: "Registry Registrar Protocol (RRP)",
                649: "Aminet",
                650: "OBEX",
                651: "IEEE MMS",
                652: "UDLR_DTCP",
                653: "RepCmd",
                654: "AODV",
                655: "TINC",
                656: "SPMP",
                657: "RMC",
                658: "TenFold",
                659: "URL Rendezvous",
                660: "MacOS Server Admin",
                661: "HAP",
                662: "PFTP",
                663: "PureNoise",
                664: "Secure Aux Bus",
                665: "Sun DR",
                666: "doom Id Software",
                667: "campaign contribution disclosures - SDR Technologies",
                668: "MeComm",
                669: "MeRegister",
                670: "VACDSM-SWS",
                671: "VACDSM-APP",
                672: "VPPS-QUA",
                673: "CIMPLEX",
                674: "ACAP",
                675: "DCTP",
                676: "VPPS Via",
                677: "Virtual Presence Protocol",
                678: "GNU Gereration Foundation NCP",
                679: "MRM",
                680: "entrust-aaas",
                681: "entrust-aams",
                682: "XFR",
                683: "CORBA IIOP",
                684: "CORBA IIOP SSL",
                685: "MDC Port Mapper",
                686: "Hardware Control Protocol Wismar",
                687: "asipregistry",
                688: "REALM-RUSD",
                689: "NMAP",
                690: "VATP",
                691: "MS Exchange Routing",
                692: "Hyperwave-ISP",
                693: "connendp",
                694: "ha-cluster",
                695: "IEEE-MMS-SSL",
                696: "RUSHD",
                697: "UUIDGEN",
                698: "OLSR",
                704: "errlog copy/server daemon",
                705: "AgentX",
                706: "SILC",
                707: "W32.Nachi Worm / Borland DSJ",
                709: "Entrust Key Management Service Handler",
                710: "Entrust Administration Service Handler",
                711: "Cisco TDP",
                729: "IBM NetView DM/6000 Server/Client",
                730: "IBM NetView DM/6000 send/tcp",
                731: "IBM NetView DM/6000 receive/tcp",
                740: "(old) NETscout Control Protocol (old)",
                741: "netGW",
                742: "Network based Rev. Cont. Sys.",
                744: "Flexible License Manager",
                747: "Fujitsu Device Control",
                748: "Russell Info Sci Calendar Manager",
                749: "kerberos administration",
                750: "rfile",
                751: "pump",
                752: "Kerberos password server",
                753: "Kerberos userreg server",
                754: "send",
                758: "nlogin",
                759: "con",
                760: "kreg, kerberos/4 registration",
                761: "kpwd, Kerberos/4 password",
                762: "quotad",
                763: "cycleserv",
                764: "omserv",
                765: "webster",
                767: "phone",
                769: "vid",
                770: "cadlock",
                771: "rtip",
                772: "cycleserv2",
                773: "submit",
                774: "rpasswd",
                775: "entomb",
                776: "wpages",
                777: "Multiling HTTP",
                780: "wpgs",
                781: "HP performance data collector",
                782: "node HP performance data managed node",
                783: "HP performance data alarm manager",
                786: "Concert",
                787: "QSC",
                799: "ControlIT / Remotely Possible",
                800: "mdbs_daemon / Remotely Possible",
                801: "device",
                808: "CCProxy",
                810: "FCP",
                828: "itm-mcell-s",
                829: "PKIX-3 CA/RA",
                871: "SUP server",
                873: "rsync",
                886: "ICL coNETion locate server",
                887: "ICL coNETion server info",
                888: "CD Database Protocol",
                900: "Check Point Firewall-1 HTTP administration / OMG Initial Refs",
                901: "Samba Web Administration Tool / Realsecure / SMPNAMERES/ NetDevil trojan",
                902: "VMware Authentication Daemon / IDEAFARM-CHAT",
                903: "IDEAFARM-CATCH / NetDevil trojan",
                911: "xact-backup",
                912: "VMware Authentication Daemon",
                989: "FTP protocol data over TLS/SSL",
                990: "FTP protocol control over TLS/SSL",
                991: "Netnews Administration System",
                992: "Telnet protocol over TLS/SSL",
                993: "IMAP4 protocol over TLS/SSL",
                994: "IRC protocol over TLS/SSL",
                995: "POP3 protocol over TLS/SSL",
                996: "vsinet",
                997: "maitrd",
                998: "busboy",
                999: "puprouter",
                1000: "cadlock",
                1002: "Microsoft Site Server Internet Locator Service (Netmeeting/ICF)",
                1008: "UFS-aware server",
                1010: "surf",
                1011: "Doly (Windows Trojan)",
                1015: "Doly (Windows Trojan)",
                1023: "Reserved",
                1024: "Reserved",
                1025: "MSTASK / network blackjack",
                1026: "MSTASK / Remote Login Network Terminal",
                1030: "BBN IAD",
                1031: "InetInfo / BBN IAD",
                1032: "BBN IAD",
                1042: "W32.Mydoom.L virus",
                1047: "Sun's NEO Object Request Broker",
                1048: "Sun's NEO Object Request Broker",
                1049: "Tobit David Postman VPMN",
                1050: "CORBA Management Agent",
                1051: "Optima VNET",
                1052: "Dynamic DNS Tools",
                1053: "Remote Assistant (RA)",
                1054: "BRVREAD",
                1055: "ANSYS - License Manager",
                1056: "VFO",
                1057: "STARTRON",
                1058: "nim",
                1059: "nimreg",
                1060: "POLESTAR",
                1061: "KIOSK",
                1062: "Veracity",
                1063: "KyoceraNetDev",
                1064: "JSTEL",
                1065: "SYSCOMLAN",
                1066: "FPO-FNS",
                1067: "Installation Bootstrap Proto. Serv.",
                1068: "Installation Bootstrap Proto. Cli.",
                1069: "COGNEX-INSIGHT",
                1070: "GMRUpdateSERV",
                1071: "BSQUARE-VOIP",
                1072: "CARDAX",
                1073: "BridgeControl",
                1074: "FASTechnologies License Manager",
                1075: "RDRMSHC",
                1076: "DAB STI-C",
                1077: "IMGames",
                1078: "eManageCstp",
                1079: "ASPROVATalk",
                1080: "Socks / W32.Beagle.AB trojan",
                1081: "PVUNIWIEN",
                1082: "AMT-ESD-PROT",
                1083: "Anasoft License Manager",
                1084: "Anasoft License Manager",
                1085: "Web Objects",
                1086: "CPL Scrambler Logging",
                1087: "CPL Scrambler Internal",
                1088: "CPL Scrambler Alarm Log",
                1089: "FF Annunciation",
                1090: "FF Fieldbus Message Specification",
                1091: "FF System Management",
                1092: "OBRPD",
                1093: "PROOFD",
                1094: "ROOTD",
                1095: "NICELink",
                1096: "Common Name Resolution Protocol",
                1097: "Sun Cluster Manager",
                1098: "RMI Activation",
                1099: "RMI Registry",
                1100: "MCTP",
                1101: "PT2-DISCOVER",
                1102: "ADOBE SERVER 1",
                1103: "ADOBE SERVER 2",
                1104: "XRL",
                1105: "FTRANHC",
                1106: "ISOIPSIGPORT-1",
                1107: "ISOIPSIGPORT-2",
                1108: "ratio-adp",
                1109: "Pop with Kerberos",
                1110: "Cluster status info",
                1111: "LM Social Server",
                1112: "Intelligent Communication Protocol",
                1114: "Mini SQL",
                1115: "ARDUS Transfer",
                1116: "ARDUS Control",
                1117: "ARDUS Multicast Transfer",
                1123: "Murray",
                1127: "SUP debugging",
                1155: "Network File Access",
                1161: "Health Polling",
                1162: "Health Trap",
                1169: "TRIPWIRE",
                1178: "SKK (kanji input)",
                1180: "Millicent Client Proxy",
                1188: "HP Web Admin",
                1200: "SCOL",
                1201: "Nucleus Sand",
                1202: "caiccipc",
                1203: "License Validation",
                1204: "Log Request Listener",
                1205: "Accord-MGC",
                1206: "Anthony Data",
                1207: "MetaSage",
                1208: "SEAGULL AIS",
                1209: "IPCD3",
                1210: "EOSS",
                1211: "Groove DPP",
                1212: "lupa",
                1213: "MPC LIFENET",
                1214: "KAZAA (Morpheus)",
                1215: "scanSTAT 1.0",
                1216: "ETEBAC 5",
                1217: "HPSS-NDAPI",
                1218: "AeroFlight-ADs",
                1219: "AeroFlight-Ret",
                1220: "QT SERVER ADMIN",
                1221: "SweetWARE Apps",
                1222: "SNI R&D network",
                1223: "TGP",
                1224: "VPNz",
                1225: "SLINKYSEARCH",
                1226: "STGXFWS",
                1227: "DNS2Go",
                1228: "FLORENCE",
                1229: "Novell ZFS",
                1234: "W32.Beagle.Y trojan / Infoseek Search Agent",
                1239: "NMSD",
                1241: "Nessus Daemon / remote message service",
                1243: "SubSeven (Windows Trojan)",
                1245: "Subseven backdoor remote access tool",
                1248: "hermes",
                1270: "Microsoft Operations Manager MOM-Encrypted",
                1300: "H323 Host Call Secure",
                1310: "Husky",
                1311: "RxMon",
                1312: "STI Envision",
                1313: "BMC_PATROLDB",
                1314: "Photoscript Distributed Printing System",
                1319: "Panja-ICSP",
                1320: "Panja-AXBNET",
                1321: "PIP",
                1335: "Digital Notary Protocol",
                1345: "VPJP",
                1346: "Alta Analytics License Manager",
                1347: "multi media conferencing",
                1348: "multi media conferencing",
                1349: "Registration Network Protocol",
                1350: "Registration Network Protocol",
                1351: "Digital Tool Works (MIT)",
                1352: "Lotus Notes",
                1353: "Relief Consulting",
                1354: "RightBrain Software",
                1355: "Intuitive Edge",
                1356: "CuillaMartin Company",
                1357: "Electronic PegBoard",
                1358: "CONNLCLI",
                1359: "FTSRV",
                1360: "MIMER",
                1361: "LinX",
                1362: "TimeFlies",
                1363: "Network DataMover Requester",
                1364: "Network DataMover Server",
                1365: "Network Software Associates",
                1366: "Novell NetWare Comm Service Platform",
                1367: "DCS",
                1368: "ScreenCast",
                1369: "GlobalView to Unix Shell",
                1370: "Unix Shell to GlobalView",
                1371: "Fujitsu Config Protocol",
                1372: "Fujitsu Config Protocol",
                1373: "Chromagrafx",
                1374: "EPI Software Systems",
                1375: "Bytex",
                1376: "IBM Person to Person Software",
                1377: "Cichlid License Manager",
                1378: "Elan License Manager",
                1379: "Integrity Solutions",
                1380: "Telesis Network License Manager",
                1381: "Apple Network License Manager",
                1382: "udt_os",
                1383: "GW Hannaway Network License Manager",
                1384: "Objective Solutions License Manager",
                1385: "Atex Publishing License Manager",
                1386: "CheckSum License Manager",
                1387: "Computer Aided Design Software Inc LM",
                1388: "Objective Solutions DataBase Cache",
                1389: "Document Manager",
                1390: "Storage Controller",
                1391: "Storage Access Server",
                1392: "Print Manager",
                1393: "Network Log Server",
                1394: "Network Log Client",
                1395: "PC Workstation Manager software",
                1396: "DVL Active Mail",
                1397: "Audio Active Mail",
                1398: "Video Active Mail",
                1399: "Cadkey License Manager",
                1400: "Cadkey Tablet Daemon",
                1401: "Goldleaf License Manager",
                1402: "Prospero Resource Manager",
                1403: "Prospero Resource Manager",
                1404: "Infinite Graphics License Manager",
                1405: "IBM Remote Execution Starter",
                1406: "NetLabs License Manager",
                1407: "DBSA License Manager",
                1408: "Sophia License Manager",
                1409: "Here License Manager",
                1410: "HiQ License Manager",
                1411: "AudioFile",
                1412: "InnoSys",
                1413: "Innosys-ACL",
                1414: "IBM MQSeries",
                1415: "DBStar",
                1416: "Novell LU6.2",
                1417: "Timbuktu Service 1 Port",
                1418: "Timbuktu Service 2 Port",
                1419: "Timbuktu Service 3 Port",
                1420: "Timbuktu Service 4 Port",
                1421: "Gandalf License Manager",
                1422: "Autodesk License Manager",
                1423: "Essbase Arbor Software",
                1424: "Hybrid Encryption Protocol",
                1425: "Zion Software License Manager",
                1426: "Satellite-data Acquisition System 1",
                1427: "mloadd monitoring tool",
                1428: "Informatik License Manager",
                1429: "Hypercom NMS",
                1430: "Hypercom TPDU",
                1431: "Reverse Gossip Transport",
                1432: "Blueberry Software License Manager",
                1433: "Microsoft-SQL-Server",
                1434: "Microsoft-SQL-Monitor",
                1435: "IBM CICS",
                1436: "Satellite-data Acquisition System 2",
                1437: "Tabula",
                1438: "Eicon Security Agent/Server",
                1439: "Eicon X25/SNA Gateway",
                1440: "Eicon Service Location Protocol",
                1441: "Cadis License Management",
                1442: "Cadis License Management",
                1443: "Integrated Engineering Software",
                1444: "Marcam License Management",
                1445: "Proxima License Manager",
                1446: "Optical Research Associates License Manager",
                1447: "Applied Parallel Research LM",
                1448: "OpenConnect License Manager",
                1449: "PEport",
                1450: "Tandem Distributed Workbench Facility",
                1451: "IBM Information Management",
                1452: "GTE Government Systems License Man",
                1453: "Genie License Manager",
                1454: "interHDL License Manager",
                1455: "ESL License Manager",
                1456: "DCA",
                1457: "Valisys License Manager",
                1458: "Nichols Research Corp.",
                1459: "Proshare Notebook Application",
                1460: "Proshare Notebook Application",
                1461: "IBM Wireless LAN",
                1462: "World License Manager",
                1463: "Nucleus",
                1464: "MSL License Manager",
                1465: "Pipes Platform",
                1466: "Ocean Software License Manager",
                1467: "CSDMBASE",
                1468: "CSDM",
                1469: "Active Analysis Limited License Manager",
                1470: "Universal Analytics",
                1471: "csdmbase",
                1472: "csdm",
                1473: "OpenMath",
                1474: "Telefinder",
                1475: "Taligent License Manager",
                1476: "clvm-cfg",
                1477: "ms-sna-server",
                1478: "ms-sna-base",
                1479: "dberegister",
                1480: "PacerForum",
                1481: "AIRS",
                1482: "Miteksys License Manager",
                1483: "AFS License Manager",
                1484: "Confluent License Manager",
                1485: "LANSource",
                1486: "nms_topo_serv",
                1487: "LocalInfoSrvr",
                1488: "DocStor",
                1489: "dmdocbroker",
                1490: "insitu-conf",
                1491: "anynetgateway",
                1492: "stone-design-1",
                1493: "netmap_lm",
                1494: "Citrix/ica",
                1495: "cvc",
                1496: "liberty-lm",
                1497: "rfx-lm",
                1498: "Sybase SQL Any",
                1499: "Federico Heinz Consultora",
                1500: "VLSI License Manager",
                1501: "Satellite-data Acquisition System 3",
                1502: "Shiva",
                1503: "MS Netmeeting / T.120 / Databeam",
                1504: "EVB Software Engineering License Manager",
                1505: "Funk Software Inc.",
                1506: "Universal Time daemon (utcd)",
                1507: "symplex",
                1508: "diagmond",
                1509: "Robcad Ltd. License Manager",
                1510: "Midland Valley Exploration Ltd. Lic. Man.",
                1511: "3l-l1",
                1512: "Microsoft's Windows Internet Name Service",
                1513: "Fujitsu Systems Business of America Inc",
                1514: "Fujitsu Systems Business of America Inc",
                1515: "ifor-protocol",
                1516: "Virtual Places Audio data",
                1517: "Virtual Places Audio control",
                1518: "Virtual Places Video data",
                1519: "Virtual Places Video control",
                1520: "atm zip office",
                1521: "Oracle8i Listener / nCube License Manager",
                1522: "Ricardo North America License Manager",
                1523: "cichild",
                1524: "dtspcd / ingres",
                1525: "Oracle / Prospero Directory Service non-priv",
                1526: "Prospero Data Access Prot non-priv",
                1527: "oracle",
                1528: "micautoreg",
                1529: "oracle",
                1530: "Oracle ExtProc (PLSExtProc) / rap-service",
                1531: "rap-listen",
                1532: "miroconnect",
                1533: "Virtual Places Software",
                1534: "micromuse-lm",
                1535: "ampr-info",
                1536: "ampr-inter",
                1537: "isi-lm",
                1538: "3ds-lm",
                1539: "Intellistor License Manager",
                1540: "rds",
                1541: "rds2",
                1542: "gridgen-elmd",
                1543: "simba-cs",
                1544: "aspeclmd",
                1545: "vistium-share",
                1546: "abbaccuray",
                1547: "laplink",
                1548: "Axon License Manager",
                1549: "Shiva Hose",
                1550: "Image Storage license manager 3M Company",
                1551: "HECMTL-DB",
                1552: "pciarray",
                1553: "sna-cs",
                1554: "CACI Products Company License Manager",
                1555: "livelan",
                1556: "AshWin CI Tecnologies",
                1557: "ArborText License Manager",
                1558: "xingmpeg",
                1559: "web2host",
                1560: "asci-val",
                1561: "facilityview",
                1562: "pconnectmgr",
                1563: "Cadabra License Manager",
                1564: "Pay-Per-View",
                1565: "WinDD",
                1566: "CORELVIDEO",
                1567: "jlicelmd",
                1568: "tsspmap",
                1569: "ets",
                1570: "orbixd",
                1571: "Oracle Remote Data Base",
                1572: "Chipcom License Manager",
                1573: "itscomm-ns",
                1574: "mvel-lm",
                1575: "oraclenames",
                1576: "moldflow-lm",
                1577: "hypercube-lm",
                1578: "Jacobus License Manager",
                1579: "ioc-sea-lm",
                1580: "tn-tl-r1",
                1581: "MIL-2045-47001",
                1582: "MSIMS",
                1583: "simbaexpress",
                1584: "tn-tl-fd2",
                1585: "intv",
                1586: "ibm-abtact",
                1587: "pra_elmd",
                1588: "triquest-lm",
                1589: "VQP",
                1590: "gemini-lm",
                1591: "ncpm-pm",
                1592: "commonspace",
                1593: "mainsoft-lm",
                1594: "sixtrak",
                1595: "radio",
                1596: "radio-sm",
                1597: "orbplus-iiop",
                1598: "picknfs",
                1599: "simbaservices",
                1600: "Bofra-A worm / issd",
                1601: "aas",
                1602: "inspect",
                1603: "pickodbc",
                1604: "icabrowser",
                1605: "Salutation Manager (Salutation Protocol)",
                1606: "Salutation Manager (SLM-API)",
                1607: "stt",
                1608: "Smart Corp. License Manager",
                1609: "isysg-lm",
                1610: "taurus-wh",
                1611: "Inter Library Loan",
                1612: "NetBill Transaction Server",
                1613: "NetBill Key Repository",
                1614: "NetBill Credential Server",
                1615: "NetBill Authorization Server",
                1616: "NetBill Product Server",
                1617: "Nimrod Inter-Agent Communication",
                1618: "skytelnet",
                1619: "xs-openstorage",
                1620: "faxportwinport",
                1621: "softdataphone",
                1622: "ontime",
                1623: "jaleosnd",
                1624: "udp-sr-port",
                1625: "svs-omagent",
                1626: "Shockwave",
                1627: "T.128 Gateway",
                1628: "LonTalk normal",
                1629: "LonTalk urgent",
                1630: "Oracle Net8 Cman",
                1631: "Visit view",
                1632: "PAMMRATC",
                1633: "PAMMRPC",
                1634: "Log On America Probe",
                1635: "EDB Server 1",
                1636: "CableNet Control Protocol",
                1637: "CableNet Admin Protocol",
                1638: "Bofra-A worm / CableNet Info Protocol",
                1639: "cert-initiator",
                1640: "cert-responder",
                1641: "InVision",
                1642: "isis-am",
                1643: "isis-ambc",
                1644: "Satellite-data Acquisition System 4",
                1645: "datametrics",
                1646: "sa-msg-port",
                1647: "rsap",
                1648: "concurrent-lm",
                1649: "kermit",
                1650: "nkd",
                1651: "shiva_confsrvr",
                1652: "xnmp",
                1653: "alphatech-lm",
                1654: "stargatealerts",
                1655: "dec-mbadmin",
                1656: "dec-mbadmin-h",
                1657: "fujitsu-mmpdc",
                1658: "sixnetudr",
                1659: "Silicon Grail License Manager",
                1660: "skip-mc-gikreq",
                1661: "netview-aix-1",
                1662: "netview-aix-2",
                1663: "netview-aix-3",
                1664: "netview-aix-4",
                1665: "netview-aix-5",
                1666: "netview-aix-6",
                1667: "netview-aix-7",
                1668: "netview-aix-8",
                1669: "netview-aix-9",
                1670: "netview-aix-10",
                1671: "netview-aix-11",
                1672: "netview-aix-12",
                1673: "Intel Proshare Multicast",
                1674: "Intel Proshare Multicast",
                1675: "Pacific Data Products",
                1676: "netcomm1",
                1677: "groupwise",
                1678: "prolink",
                1679: "darcorp-lm",
                1680: "microcom-sbp",
                1681: "sd-elmd",
                1682: "lanyon-lantern",
                1683: "ncpm-hip",
                1684: "SnareSecure",
                1685: "n2nremote",
                1686: "cvmon",
                1687: "nsjtp-ctrl",
                1688: "nsjtp-data",
                1689: "firefox",
                1690: "ng-umds",
                1691: "empire-empuma",
                1692: "sstsys-lm",
                1693: "rrirtr",
                1694: "rrimwm",
                1695: "rrilwm",
                1696: "rrifmm",
                1697: "rrisat",
                1698: "RSVP-ENCAPSULATION-1",
                1699: "RSVP-ENCAPSULATION-2",
                1700: "mps-raft",
                1701: "l2tp / AOL",
                1702: "deskshare",
                1703: "hb-engine",
                1704: "bcs-broker",
                1705: "slingshot",
                1706: "jetform",
                1707: "vdmplay",
                1708: "gat-lmd",
                1709: "centra",
                1710: "impera",
                1711: "pptconference",
                1712: "resource monitoring service",
                1713: "ConferenceTalk",
                1714: "sesi-lm",
                1715: "houdini-lm",
                1716: "xmsg",
                1717: "fj-hdnet",
                1718: "h323gatedisc",
                1719: "h323gatestat",
                1720: "h323hostcall",
                1721: "caicci",
                1722: "HKS License Manager",
                1723: "pptp",
                1724: "csbphonemaster",
                1725: "iden-ralp",
                1726: "IBERIAGAMES",
                1727: "winddx",
                1728: "TELINDUS",
                1729: "CityNL License Management",
                1730: "roketz",
                1731: "MS Netmeeting / Audio call control / MSICCP",
                1732: "proxim",
                1733: "SIMS - SIIPAT Protocol for Alarm Transmission",
                1734: "Camber Corporation License Management",
                1735: "PrivateChat",
                1736: "street-stream",
                1737: "ultimad",
                1738: "GameGen1",
                1739: "webaccess",
                1740: "encore",
                1741: "cisco-net-mgmt",
                1742: "3Com-nsd",
                1743: "Cinema Graphics License Manager",
                1744: "ncpm-ft",
                1745: "ISA Server proxy autoconfig / Remote Winsock",
                1746: "ftrapid-1",
                1747: "ftrapid-2",
                1748: "oracle-em1",
                1749: "aspen-services",
                1750: "Simple Socket Library's PortMaster",
                1751: "SwiftNet",
                1752: "Leap of Faith Research License Manager",
                1753: "Translogic License Manager",
                1754: "oracle-em2",
                1755: "Microsoft Streaming Server",
                1756: "capfast-lmd",
                1757: "cnhrp",
                1758: "tftp-mcast",
                1759: "SPSS License Manager",
                1760: "www-ldap-gw",
                1761: "cft-0",
                1762: "cft-1",
                1763: "cft-2",
                1764: "cft-3",
                1765: "cft-4",
                1766: "cft-5",
                1767: "cft-6",
                1768: "cft-7",
                1769: "bmc-net-adm",
                1770: "bmc-net-svc",
                1771: "vaultbase",
                1772: "EssWeb Gateway",
                1773: "KMSControl",
                1774: "global-dtserv",
                1776: "Federal Emergency Management Information System",
                1777: "powerguardian",
                1778: "prodigy-internet",
                1779: "pharmasoft",
                1780: "dpkeyserv",
                1781: "answersoft-lm",
                1782: "HP JetSend",
                1783: "Port 04/14/00 fujitsu.co.jp",
                1784: "Finle License Manager",
                1785: "Wind River Systems License Manager",
                1786: "funk-logger",
                1787: "funk-license",
                1788: "psmond",
                1789: "hello",
                1790: "Narrative Media Streaming Protocol",
                1791: "EA1",
                1792: "ibm-dt-2",
                1793: "rsc-robot",
                1794: "cera-bcm",
                1795: "dpi-proxy",
                1796: "Vocaltec Server Administration",
                1797: "UMA",
                1798: "Event Transfer Protocol",
                1799: "NETRISK",
                1800: "ANSYS-License manager",
                1801: "Microsoft Message Queuing",
                1802: "ConComp1",
                1803: "HP-HCIP-GWY",
                1804: "ENL",
                1805: "ENL-Name",
                1806: "Musiconline",
                1807: "Fujitsu Hot Standby Protocol",
                1808: "Oracle-VP2",
                1809: "Oracle-VP1",
                1810: "Jerand License Manager",
                1811: "Scientia-SDB",
                1812: "RADIUS",
                1813: "RADIUS Accounting / HackTool.SkSocket",
                1814: "TDP Suite",
                1815: "MMPFT",
                1816: "HARP",
                1817: "RKB-OSCS",
                1818: "Enhanced Trivial File Transfer Protocol",
                1819: "Plato License Manager",
                1820: "mcagent",
                1821: "donnyworld",
                1822: "es-elmd",
                1823: "Unisys Natural Language License Manager",
                1824: "metrics-pas",
                1825: "DirecPC Video",
                1826: "ARDT",
                1827: "ASI",
                1828: "itm-mcell-u",
                1829: "Optika eMedia",
                1830: "Oracle Net8 CMan Admin",
                1831: "Myrtle",
                1832: "ThoughtTreasure",
                1833: "udpradio",
                1834: "ARDUS Unicast",
                1835: "ARDUS Multicast",
                1836: "ste-smsc",
                1837: "csoft1",
                1838: "TALNET",
                1839: "netopia-vo1",
                1840: "netopia-vo2",
                1841: "netopia-vo3",
                1842: "netopia-vo4",
                1843: "netopia-vo5",
                1844: "DirecPC-DLL",
                1850: "GSI",
                1851: "ctcd",
                1860: "SunSCALAR Services",
                1861: "LeCroy VICP",
                1862: "techra-server",
                1863: "MSN Messenger",
                1864: "Paradym 31 Port",
                1865: "ENTP",
                1870: "SunSCALAR DNS Service",
                1871: "Cano Central 0",
                1872: "Cano Central 1",
                1873: "Fjmpjps",
                1874: "Fjswapsnp",
                1881: "IBM MQSeries",
                1895: "Vista 4GL",
                1899: "MC2Studios",
                1900: "SSDP",
                1901: "Fujitsu ICL Terminal Emulator Program A",
                1902: "Fujitsu ICL Terminal Emulator Program B",
                1903: "Local Link Name Resolution",
                1904: "Fujitsu ICL Terminal Emulator Program C",
                1905: "Secure UP.Link Gateway Protocol",
                1906: "TPortMapperReq",
                1907: "IntraSTAR",
                1908: "Dawn",
                1909: "Global World Link",
                1910: "ultrabac",
                1911: "Starlight Networks Multimedia Transport Protocol",
                1912: "rhp-iibp",
                1913: "armadp",
                1914: "Elm-Momentum",
                1915: "FACELINK",
                1916: "Persoft Persona",
                1917: "nOAgent",
                1918: "Candle Directory Service - NDS",
                1919: "Candle Directory Service - DCH",
                1920: "Candle Directory Service - FERRET",
                1921: "NoAdmin",
                1922: "Tapestry",
                1923: "SPICE",
                1924: "XIIP",
                1930: "Drive AppServer",
                1931: "AMD SCHED",
                1944: "close-combat",
                1945: "dialogic-elmd",
                1946: "tekpls",
                1947: "hlserver",
                1948: "eye2eye",
                1949: "ISMA Easdaq Live",
                1950: "ISMA Easdaq Test",
                1951: "bcs-lmserver",
                1952: "mpnjsc",
                1953: "Rapid Base",
                1961: "BTS APPSERVER",
                1962: "BIAP-MP",
                1963: "WebMachine",
                1964: "SOLID E ENGINE",
                1965: "Tivoli NPM",
                1966: "Slush",
                1967: "SNS Quote",
                1972: "Cache",
                1973: "Data Link Switching Remote Access Protocol",
                1974: "DRP",
                1975: "TCO Flash Agent",
                1976: "TCO Reg Agent",
                1977: "TCO Address Book",
                1978: "UniSQL",
                1979: "UniSQL Java",
                1984: "BB",
                1985: "Hot Standby Router Protocol",
                1986: "cisco license management",
                1987: "cisco RSRB Priority 1 port",
                1988: "cisco RSRB Priority 2 port",
                1989: "MHSnet system",
                1990: "cisco STUN Priority 1 port",
                1991: "cisco STUN Priority 2 port",
                1992: "IPsendmsg",
                1993: "cisco SNMP TCP port",
                1994: "cisco serial tunnel port",
                1995: "cisco perf port",
                1996: "cisco Remote SRB port",
                1997: "cisco Gateway Discovery Protocol",
                1998: "cisco X.25 service (XOT)",
                1999: "cisco identification port / SubSeven (Windows Trojan) / Backdoor (Windows Trojan)",
                2000: "Remotely Anywhere / VIA NET.WORKS PostOffice Plus",
                2001: "Cisco mgmt / Remotely Anywhere",
                2002: "globe",
                2003: "GNU finger",
                2004: "mailbox",
                2005: "encrypted symmetric telnet/login",
                2006: "invokator",
                2007: "dectalk",
                2008: "conf",
                2009: "news",
                2010: "search",
                2011: "raid",
                2012: "ttyinfo",
                2013: "raid-am",
                2014: "troff",
                2015: "cypress",
                2016: "bootserver",
                2017: "cypress-stat",
                2018: "terminaldb",
                2019: "whosockami",
                2020: "xinupageserver",
                2021: "servexec",
                2022: "down",
                2023: "xinuexpansion3",
                2024: "xinuexpansion4",
                2025: "ellpack",
                2026: "scrabble",
                2027: "shadowserver",
                2028: "submitserver",
                2030: "device2",
                2032: "blackboard",
                2033: "glogger",
                2034: "scoremgr",
                2035: "imsldoc",
                2038: "objectmanager",
                2040: "lam",
                2041: "W32.Korgo Worm / interbase",
                2042: "isis",
                2043: "isis-bcast",
                2044: "rimsl",
                2045: "cdfunc",
                2046: "sdfunc",
                2047: "dls",
                2048: "dls-monitor",
                2049: "Network File System - Sun Microsystems",
                2053: "Kerberos de-multiplexer",
                2054: "distrib-net",
                2065: "Data Link Switch Read Port Number",
                2067: "Data Link Switch Write Port Number",
                2080: "Wingate",
                2090: "Load Report Protocol",
                2091: "PRP",
                2092: "Descent 3",
                2093: "NBX CC",
                2094: "NBX AU",
                2095: "NBX SER",
                2096: "NBX DIR",
                2097: "Jet Form Preview",
                2098: "Dialog Port",
                2099: "H.225.0 Annex G",
                2100: "amiganetfs",
                2101: "Microsoft Message Queuing / rtcm-sc104",
                2102: "Zephyr server",
                2103: "Microsoft Message Queuing RPC / Zephyr serv-hm connection",
                2104: "Zephyr hostmanager",
                2105: "Microsoft Message Queuing RPC / MiniPay",
                2106: "MZAP",
                2107: "Microsoft Message Queuing Management / BinTec Admin",
                2108: "Comcam",
                2109: "Ergolight",
                2110: "UMSP",
                2111: "DSATP",
                2112: "Idonix MetaNet",
                2113: "HSL StoRM",
                2114: "NEWHEIGHTS",
                2115: "KDM / Bugs (Windows Trojan)",
                2116: "CCOWCMR",
                2117: "MENTACLIENT",
                2118: "MENTASERVER",
                2119: "GSIGATEKEEPER",
                2120: "Quick Eagle Networks CP",
                2121: "CCProxy FTP / SCIENTIA-SSDB",
                2122: "CauPC Remote Control",
                2123: "GTP-Control Plane (3GPP)",
                2124: "ELATELINK",
                2125: "LOCKSTEP",
                2126: "PktCable-COPS",
                2127: "INDEX-PC-WB",
                2128: "Net Steward Control",
                2129: "cs-live.com",
                2130: "SWC-XDS",
                2131: "Avantageb2b",
                2132: "AVAIL-EPMAP",
                2133: "ZYMED-ZPP",
                2134: "AVENUE",
                2135: "Grid Resource Information Server",
                2136: "APPWORXSRV",
                2137: "CONNECT",
                2138: "UNBIND-CLUSTER",
                2139: "IAS-AUTH",
                2140: "IAS-REG",
                2141: "IAS-ADMIND",
                2142: "TDM-OVER-IP",
                2143: "Live Vault Job Control",
                2144: "Live Vault Fast Object Transfer",
                2145: "Live Vault Remote Diagnostic Console Support",
                2146: "Live Vault Admin Event Notification",
                2147: "Live Vault Authentication",
                2148: "VERITAS UNIVERSAL COMMUNICATION LAYER",
                2149: "ACPTSYS",
                2150: "DYNAMIC3D",
                2151: "DOCENT",
                2152: "GTP-User Plane (3GPP)",
                2165: "X-Bone API",
                2166: "IWSERVER",
                2180: "Millicent Vendor Gateway Server",
                2181: "eforward",
                2190: "TiVoConnect Beacon",
                2191: "TvBus Messaging",
                2200: "ICI",
                2201: "Advanced Training System Program",
                2202: "Int. Multimedia Teleconferencing Cosortium",
                2213: "Kali",
                2220: "Ganymede",
                2221: "Rockwell CSP1",
                2222: "Rockwell CSP2",
                2223: "Rockwell CSP3",
                2232: "IVS Video default",
                2233: "INFOCRYPT",
                2234: "DirectPlay",
                2235: "Sercomm-WLink",
                2236: "Nani",
                2237: "Optech Port1 License Manager",
                2238: "AVIVA SNA SERVER",
                2239: "Image Query",
                2240: "RECIPe",
                2241: "IVS Daemon",
                2242: "Folio Remote Server",
                2243: "Magicom Protocol",
                2244: "NMS Server",
                2245: "HaO",
                2279: "xmquery",
                2280: "LNVPOLLER",
                2281: "LNVCONSOLE",
                2282: "LNVALARM",
                2283: "Dumaru.Y (Windows trojan) / LNVSTATUS",
                2284: "LNVMAPS",
                2285: "LNVMAILMON",
                2286: "NAS-Metering",
                2287: "DNA",
                2288: "NETML",
                2294: "Konshus License Manager (FLEX)",
                2295: "Advant License Manager",
                2296: "Theta License Manager (Rainbow)",
                2297: "D2K DataMover 1",
                2298: "D2K DataMover 2",
                2299: "PC Telecommute",
                2300: "CVMMON",
                2301: "Compaq HTTP",
                2302: "Bindery Support",
                2303: "Proxy Gateway",
                2304: "Attachmate UTS",
                2305: "MT ScaleServer",
                2306: "TAPPI BoxNet",
                2307: "pehelp",
                2308: "sdhelp",
                2309: "SD Server",
                2310: "SD Client",
                2311: "Message Service",
                2313: "IAPP (Inter Access Point Protocol)",
                2314: "CR WebSystems",
                2315: "Precise Sft.",
                2316: "SENT License Manager",
                2317: "Attachmate G32",
                2318: "Cadence Control",
                2319: "InfoLibria",
                2320: "Siebel NS",
                2321: "RDLAP over UDP",
                2322: "ofsd",
                2323: "3d-nfsd",
                2324: "Cosmocall",
                2325: "Design Space License Management",
                2326: "IDCP",
                2327: "xingcsm",
                2328: "Netrix SFTM",
                2329: "NVD",
                2330: "TSCCHAT",
                2331: "AGENTVIEW",
                2332: "RCC Host",
                2333: "SNAPP",
                2334: "ACE Client Auth",
                2335: "ACE Proxy",
                2336: "Apple UG Control",
                2337: "ideesrv",
                2338: "Norton Lambert",
                2339: "3Com WebView",
                2340: "WRS Registry",
                2341: "XIO Status",
                2342: "Seagate Manage Exec",
                2343: "nati logos",
                2344: "fcmsys",
                2345: "dbm",
                2346: "Game Connection Port",
                2347: "Game Announcement and Location",
                2348: "Information to query for game status",
                2349: "Diagnostics Port",
                2350: "psbserver",
                2351: "psrserver",
                2352: "pslserver",
                2353: "pspserver",
                2354: "psprserver",
                2355: "psdbserver",
                2356: "GXT License Managemant",
                2357: "UniHub Server",
                2358: "Futrix",
                2359: "FlukeServer",
                2360: "NexstorIndLtd",
                2361: "TL1",
                2362: "digiman",
                2363: "Media Central NFSD",
                2364: "OI-2000",
                2365: "dbref",
                2366: "qip-login",
                2367: "Service Control",
                2368: "OpenTable",
                2369: "ACS2000 DSP",
                2370: "L3-HBMon",
                2381: "Compaq HTTPS",
                2382: "Microsoft OLAP",
                2383: "Microsoft OLAP",
                2384: "SD-REQUEST",
                2389: "OpenView Session Mgr",
                2390: "RSMTP",
                2391: "3COM Net Management",
                2392: "Tactical Auth",
                2393: "MS OLAP 1",
                2394: "MS OLAP 2",
                2395: "LAN900 Remote",
                2396: "Wusage",
                2397: "NCL",
                2398: "Orbiter",
                2399: "FileMaker Inc. - Data Access Layer",
                2400: "OpEquus Server",
                2401: "cvspserver",
                2402: "TaskMaster 2000 Server",
                2403: "TaskMaster 2000 Web",
                2404: "IEC870-5-104",
                2405: "TRC Netpoll",
                2406: "JediServer",
                2407: "Orion",
                2408: "OptimaNet",
                2409: "SNS Protocol",
                2410: "VRTS Registry",
                2411: "Netwave AP Management",
                2412: "CDN",
                2413: "orion-rmi-reg",
                2414: "Interlingua",
                2415: "COMTEST",
                2416: "RMT Server",
                2417: "Composit Server",
                2418: "cas",
                2419: "Attachmate S2S",
                2420: "DSL Remote Management",
                2421: "G-Talk",
                2422: "CRMSBITS",
                2423: "RNRP",
                2424: "KOFAX-SVR",
                2425: "Fujitsu App Manager",
                2426: "Appliant TCP",
                2427: "Media Gateway Control Protocol Gateway",
                2428: "One Way Trip Time",
                2429: "FT-ROLE",
                2430: "venus",
                2431: "venus-se",
                2432: "codasrv",
                2433: "codasrv-se",
                2434: "pxc-epmap",
                2435: "OptiLogic",
                2436: "TOP/X",
                2437: "UniControl",
                2438: "MSP",
                2439: "SybaseDBSynch",
                2440: "Spearway Lockers",
                2441: "pvsw-inet",
                2442: "Netangel",
                2443: "PowerClient Central Storage Facility",
                2444: "BT PP2 Sectrans",
                2445: "DTN1",
                2446: "bues_service",
                2447: "OpenView NNM daemon",
                2448: "hpppsvr",
                2449: "RATL",
                2450: "netadmin",
                2451: "netchat",
                2452: "SnifferClient",
                2453: "madge-om",
                2454: "IndX-DDS",
                2455: "WAGO-IO-SYSTEM",
                2456: "altav-remmgt",
                2457: "Rapido_IP",
                2458: "griffin",
                2459: "Community",
                2460: "ms-theater",
                2461: "qadmifoper",
                2462: "qadmifevent",
                2463: "Symbios Raid",
                2464: "DirecPC SI",
                2465: "Load Balance Management",
                2466: "Load Balance Forwarding",
                2467: "High Criteria",
                2468: "qip_msgd",
                2469: "MTI-TCS-COMM",
                2470: "taskman port",
                2471: "SeaODBC",
                2472: "C3",
                2473: "Aker-cdp",
                2474: "Vital Analysis",
                2475: "ACE Server",
                2476: "ACE Server Propagation",
                2477: "SecurSight Certificate Valifation Service",
                2478: "SecurSight Authentication Server (SLL)",
                2479: "SecurSight Event Logging Server (SSL)",
                2480: "Lingwood's Detail",
                2481: "Oracle GIOP",
                2482: "Oracle GIOP SSL",
                2483: "Oracle TTC",
                2484: "Oracle TTC SSL",
                2485: "Net Objects1",
                2486: "Net Objects2",
                2487: "Policy Notice Service",
                2488: "Moy Corporation",
                2489: "TSILB",
                2490: "qip_qdhcp",
                2491: "Conclave CPP",
                2492: "GROOVE",
                2493: "Talarian MQS",
                2494: "BMC AR",
                2495: "Fast Remote Services",
                2496: "DIRGIS",
                2497: "Quad DB",
                2498: "ODN-CasTraq",
                2499: "UniControl",
                2500: "Resource Tracking system server",
                2501: "Resource Tracking system client",
                2502: "Kentrox Protocol",
                2503: "NMS-DPNSS",
                2504: "WLBS",
                2505: "torque-traffic",
                2506: "jbroker",
                2507: "spock",
                2508: "JDataStore",
                2509: "fjmpss",
                2510: "fjappmgrbulk",
                2511: "Metastorm",
                2512: "Citrix IMA",
                2513: "Citrix ADMIN",
                2514: "Facsys NTP",
                2515: "Facsys Router",
                2516: "Main Control",
                2517: "H.323 Annex E call signaling transport",
                2518: "Willy",
                2519: "globmsgsvc",
                2520: "pvsw",
                2521: "Adaptec Manager",
                2522: "WinDb",
                2523: "Qke LLC V.3",
                2524: "Optiwave License Management",
                2525: "MS V-Worlds",
                2526: "EMA License Manager",
                2527: "IQ Server",
                2528: "NCR CCL",
                2529: "UTS FTP",
                2530: "VR Commerce",
                2531: "ITO-E GUI",
                2532: "OVTOPMD",
                2533: "SnifferServer",
                2534: "Combox Web Access",
                2535: "W32.Beagle trojan / MADCAP",
                2536: "btpp2audctr1",
                2537: "Upgrade Protocol",
                2538: "vnwk-prapi",
                2539: "VSI Admin",
                2540: "LonWorks",
                2541: "LonWorks2",
                2542: "daVinci",
                2543: "REFTEK",
                2544: "Novell ZEN",
                2545: "sis-emt",
                2546: "vytalvaultbrtp",
                2547: "vytalvaultvsmp",
                2548: "vytalvaultpipe",
                2549: "IPASS",
                2550: "ADS",
                2551: "ISG UDA Server",
                2552: "Call Logging",
                2553: "efidiningport",
                2554: "VCnet-Link v10",
                2555: "Compaq WCP",
                2556: "W32.Beagle.N trojan / MADCAP / nicetec-nmsvc",
                2557: "nicetec-mgmt",
                2558: "PCLE Multi Media",
                2559: "LSTP",
                2560: "labrat",
                2561: "MosaixCC",
                2562: "Delibo",
                2563: "CTI Redwood",
                2564: "HP 3000 NS/VT block mode telnet",
                2565: "Coordinator Server",
                2566: "pcs-pcw",
                2567: "Cisco Line Protocol",
                2568: "SPAM TRAP",
                2569: "Sonus Call Signal",
                2570: "HS Port",
                2571: "CECSVC",
                2572: "IBP",
                2573: "Trust Establish",
                2574: "Blockade BPSP",
                2575: "HL7",
                2576: "TCL Pro Debugger",
                2577: "Scriptics Lsrvr",
                2578: "RVS ISDN DCP",
                2579: "mpfoncl",
                2580: "Tributary",
                2581: "ARGIS TE",
                2582: "ARGIS DS",
                2583: "MON / Wincrash2",
                2584: "cyaserv",
                2585: "NETX Server",
                2586: "NETX Agent",
                2587: "MASC",
                2588: "Privilege",
                2589: "quartus tcl",
                2590: "idotdist",
                2591: "Maytag Shuffle",
                2592: "netrek",
                2593: "MNS Mail Notice Service",
                2594: "Data Base Server",
                2595: "World Fusion 1",
                2596: "World Fusion 2",
                2597: "Homestead Glory",
                2598: "Citrix MA Client",
                2599: "Meridian Data",
                2600: "HPSTGMGR",
                2601: "discp client",
                2602: "discp server",
                2603: "Service Meter",
                2604: "NSC CCS",
                2605: "NSC POSA",
                2606: "Dell Netmon",
                2607: "Dell Connection",
                2608: "Wag Service",
                2609: "System Monitor",
                2610: "VersaTek",
                2611: "LIONHEAD",
                2612: "Qpasa Agent",
                2613: "SMNTUBootstrap",
                2614: "Never Offline",
                2615: "firepower",
                2616: "appswitch-emp",
                2617: "Clinical Context Managers",
                2618: "Priority E-Com",
                2619: "bruce",
                2620: "LPSRecommender",
                2621: "Miles Apart Jukebox Server",
                2622: "MetricaDBC",
                2623: "LMDP",
                2624: "Aria",
                2625: "Blwnkl Port",
                2626: "gbjd816",
                2627: "Moshe Beeri",
                2628: "DICT",
                2629: "Sitara Server",
                2630: "Sitara Management",
                2631: "Sitara Dir",
                2632: "IRdg Post",
                2633: "InterIntelli",
                2634: "PK Electronics",
                2635: "Back Burner",
                2636: "Solve",
                2637: "Import Document Service",
                2638: "Sybase Anywhere",
                2639: "AMInet",
                2640: "Sabbagh Associates Licence Manager",
                2641: "HDL Server",
                2642: "Tragic",
                2643: "GTE-SAMP",
                2644: "Travsoft IPX Tunnel",
                2645: "Novell IPX CMD",
                2646: "AND Licence Manager",
                2647: "SyncServer",
                2648: "Upsnotifyprot",
                2649: "VPSIPPORT",
                2650: "eristwoguns",
                2651: "EBInSite",
                2652: "InterPathPanel",
                2653: "Sonus",
                2654: "Corel VNC Admin",
                2655: "UNIX Nt Glue",
                2656: "Kana",
                2657: "SNS Dispatcher",
                2658: "SNS Admin",
                2659: "SNS Query",
                2660: "GC Monitor",
                2661: "OLHOST",
                2662: "BinTec-CAPI",
                2663: "BinTec-TAPI",
                2664: "Command MQ GM",
                2665: "Command MQ PM",
                2666: "extensis",
                2667: "Alarm Clock Server",
                2668: "Alarm Clock Client",
                2669: "TOAD",
                2670: "TVE Announce",
                2671: "newlixreg",
                2672: "nhserver",
                2673: "First Call 42",
                2674: "ewnn",
                2675: "TTC ETAP",
                2676: "SIMSLink",
                2677: "Gadget Gate 1 Way",
                2678: "Gadget Gate 2 Way",
                2679: "Sync Server SSL",
                2680: "pxc-sapxom",
                2681: "mpnjsomb",
                2682: "SRSP",
                2683: "NCDLoadBalance",
                2684: "mpnjsosv",
                2685: "mpnjsocl",
                2686: "mpnjsomg",
                2687: "pq-lic-mgmt",
                2688: "md-cf-HTTP",
                2689: "FastLynx",
                2690: "HP NNM Embedded Database",
                2691: "IT Internet",
                2692: "Admins LMS",
                2693: "belarc-HTTP",
                2694: "pwrsevent",
                2695: "VSPREAD",
                2696: "Unify Admin",
                2697: "Oce SNMP Trap Port",
                2698: "MCK-IVPIP",
                2699: "Csoft Plus Client",
                2700: "tqdata",
                2701: "SMS Remote Control (control)",
                2702: "SMS Remote Control (data)",
                2703: "SMS Remote Control (chat)",
                2704: "SMS Remote File Transfer",
                2705: "SDS Admin",
                2706: "NCD Mirroring",
                2707: "EMCSYMAPIPORT",
                2708: "Banyan-Net",
                2709: "Supermon",
                2710: "SSO Service",
                2711: "SSO Control",
                2712: "Axapta Object Communication Protocol",
                2713: "Raven1",
                2714: "Raven2",
                2715: "HPSTGMGR2",
                2716: "Inova IP Disco",
                2717: "PN REQUESTER",
                2718: "PN REQUESTER 2",
                2719: "Scan & Change",
                2720: "wkars",
                2721: "Smart Diagnose",
                2722: "Proactive Server",
                2723: "WatchDog NT",
                2724: "qotps",
                2725: "SQL Analysis Services / MSOLAP PTP2",
                2726: "TAMS",
                2727: "Media Gateway Control Protocol Call Agent",
                2728: "SQDR",
                2729: "TCIM Control",
                2730: "NEC RaidPlus",
                2731: "NetDragon Messanger",
                2732: "G5M",
                2733: "Signet CTF",
                2734: "CCS Software",
                2735: "Monitor Console",
                2736: "RADWIZ NMS SRV",
                2737: "SRP Feedback",
                2738: "NDL TCP-OSI Gateway",
                2739: "TN Timing",
                2740: "Alarm",
                2741: "TSB",
                2742: "TSB2",
                2743: "murx",
                2744: "honyaku",
                2745: "W32.Beagle.C trojan) / URBISNET",
                2746: "CPUDPENCAP",
                2747: "yk.fujitsu.co.jp",
                2748: "yk.fujitsu.co.jp",
                2749: "yk.fujitsu.co.jp",
                2750: "yk.fujitsu.co.jp",
                2751: "yk.fujitsu.co.jp",
                2752: "RSISYS ACCESS",
                2753: "de-spot",
                2754: "APOLLO CC",
                2755: "Express Pay",
                2756: "simplement-tie",
                2757: "CNRP",
                2758: "APOLLO Status",
                2759: "APOLLO GMS",
                2760: "Saba MS",
                2761: "DICOM ISCL",
                2762: "DICOM TLS",
                2763: "Desktop DNA",
                2764: "Data Insurance",
                2765: "qip-audup",
                2766: "Compaq SCP",
                2767: "UADTC",
                2768: "UACS",
                2769: "Single Point MVS",
                2770: "Veronica",
                2771: "Vergence CM",
                2772: "auris",
                2773: "PC Backup",
                2774: "PC Backup",
                2775: "SMMP",
                2776: "Ridgeway Systems & Software",
                2777: "Ridgeway Systems & Software",
                2778: "Gwen-Sonya",
                2779: "LBC Sync",
                2780: "LBC Control",
                2781: "whosells",
                2782: "everydayrc",
                2783: "AISES",
                2784: "world wide web - development",
                2785: "aic-np",
                2786: "aic-oncrpc - Destiny MCD database",
                2787: "piccolo - Cornerstone Software",
                2788: "NetWare Loadable Module - Seagate Software",
                2789: "Media Agent",
                2790: "PLG Proxy",
                2791: "MT Port Registrator",
                2792: "f5-globalsite",
                2793: "initlsmsad",
                2794: "aaftp",
                2795: "LiveStats",
                2796: "ac-tech",
                2797: "esp-encap",
                2798: "TMESIS-UPShot",
                2799: "ICON Discover",
                2800: "ACC RAID",
                2801: "IGCP",
                2802: "Veritas TCP1",
                2803: "btprjctrl",
                2804: "Telexis VTU",
                2805: "WTA WSP-S",
                2806: "cspuni",
                2807: "cspmulti",
                2808: "J-LAN-P",
                2809: "CORBA LOC",
                2810: "Active Net Steward",
                2811: "GSI FTP",
                2812: "atmtcp",
                2813: "llm-pass",
                2814: "llm-csv",
                2815: "LBC Measurement",
                2816: "LBC Watchdog",
                2817: "NMSig Port",
                2818: "rmlnk",
                2819: "FC Fault Notification",
                2820: "UniVision",
                2821: "vml_dms",
                2822: "ka0wuc",
                2823: "CQG Net/LAN",
                2826: "slc systemlog",
                2827: "slc ctrlrloops",
                2828: "ITM License Manager",
                2829: "silkp1",
                2830: "silkp2",
                2831: "silkp3",
                2832: "silkp4",
                2833: "glishd",
                2834: "EVTP",
                2835: "EVTP-DATA",
                2836: "catalyst",
                2837: "Repliweb",
                2838: "Starbot",
                2839: "NMSigPort",
                2840: "l3-exprt",
                2841: "l3-ranger",
                2842: "l3-hawk",
                2843: "PDnet",
                2844: "BPCP POLL",
                2845: "BPCP TRAP",
                2846: "AIMPP Hello",
                2847: "AIMPP Port Req",
                2848: "AMT-BLC-PORT",
                2849: "FXP",
                2850: "MetaConsole",
                2851: "webemshttp",
                2852: "bears-01",
                2853: "ISPipes",
                2854: "InfoMover",
                2856: "cesdinv",
                2857: "SimCtIP",
                2858: "ECNP",
                2859: "Active Memory",
                2860: "Dialpad Voice 1",
                2861: "Dialpad Voice 2",
                2862: "TTG Protocol",
                2863: "Sonar Data",
                2864: "main 5001 cmd",
                2865: "pit-vpn",
                2866: "lwlistener",
                2867: "esps-portal",
                2868: "NPEP Messaging",
                2869: "SSDP event notification / ICSLAP",
                2870: "daishi",
                2871: "MSI Select Play",
                2872: "CONTRACT",
                2873: "PASPAR2 ZoomIn",
                2874: "dxmessagebase1",
                2875: "dxmessagebase2",
                2876: "SPS Tunnel",
                2877: "BLUELANCE",
                2878: "AAP",
                2879: "ucentric-ds",
                2880: "synapse",
                2881: "NDSP",
                2882: "NDTP",
                2883: "NDNP",
                2884: "Flash Msg",
                2885: "TopFlow",
                2886: "RESPONSELOGIC",
                2887: "aironet",
                2888: "SPCSDLOBBY",
                2889: "RSOM",
                2890: "CSPCLMULTI",
                2891: "CINEGRFX-ELMD License Manager",
                2892: "SNIFFERDATA",
                2893: "VSECONNECTOR",
                2894: "ABACUS-REMOTE",
                2895: "NATUS LINK",
                2896: "ECOVISIONG6-1",
                2897: "Citrix RTMP",
                2898: "APPLIANCE-CFG",
                2899: "case.nm.fujitsu.co.jp",
                2900: "magisoft.com",
                2901: "ALLSTORCNS",
                2902: "NET ASPI",
                2903: "SUITCASE",
                2904: "M2UA",
                2905: "M3UA",
                2906: "CALLER9",
                2907: "WEBMETHODS B2B",
                2908: "mao",
                2909: "Funk Dialout",
                2910: "TDAccess",
                2911: "Blockade",
                2912: "Epicon",
                2913: "Booster Ware",
                2914: "Game Lobby",
                2915: "TK Socket",
                2916: "Elvin Server",
                2917: "Elvin Client",
                2918: "Kasten Chase Pad",
                2919: "ROBOER",
                2920: "ROBOEDA",
                2921: "CESD Contents Delivery Management",
                2922: "CESD Contents Delivery Data Transfer",
                2923: "WTA-WSP-WTP-S",
                2924: "PRECISE-VIP",
                2925: "Firewall Redundancy Protocol",
                2926: "MOBILE-FILE-DL",
                2927: "UNIMOBILECTRL",
                2928: "REDSTONE-CPSS",
                2929: "PANJA-WEBADMIN",
                2930: "PANJA-WEBLINX",
                2931: "Circle-X",
                2932: "INCP",
                2933: "4-TIER OPM GW",
                2934: "4-TIER OPM CLI",
                2935: "QTP",
                2936: "OTPatch",
                2937: "PNACONSULT-LM",
                2938: "SM-PAS-1",
                2939: "SM-PAS-2",
                2940: "SM-PAS-3",
                2941: "SM-PAS-4",
                2942: "SM-PAS-5",
                2943: "TTNRepository",
                2944: "Megaco H-248",
                2945: "H248 Binary",
                2946: "FJSVmpor",
                2947: "GPSD",
                2948: "WAP PUSH",
                2949: "WAP PUSH SECURE",
                2950: "ESIP",
                2951: "OTTP",
                2952: "MPFWSAS",
                2953: "OVALARMSRV",
                2954: "OVALARMSRV-CMD",
                2955: "CSNOTIFY",
                2956: "OVRIMOSDBMAN",
                2957: "JAMCT5",
                2958: "JAMCT6",
                2959: "RMOPAGT",
                2960: "DFOXSERVER",
                2961: "BOLDSOFT-LM",
                2962: "IPH-POLICY-CLI",
                2963: "IPH-POLICY-ADM",
                2964: "BULLANT SRAP",
                2965: "BULLANT RAP",
                2966: "IDP-INFOTRIEVE",
                2967: "SSC-AGENT",
                2968: "ENPP",
                2969: "UPnP / ESSP",
                2970: "INDEX-NET",
                2971: "Net Clip",
                2972: "PMSM Webrctl",
                2973: "SV Networks",
                2974: "Signal",
                2975: "Fujitsu Configuration Management Service",
                2976: "CNS Server Port",
                2977: "TTCs Enterprise Test Access Protocol - NS",
                2978: "TTCs Enterprise Test Access Protocol - DS",
                2979: "H.263 Video Streaming",
                2980: "Instant Messaging Service",
                2981: "MYLXAMPORT",
                2982: "IWB-WHITEBOARD",
                2983: "NETPLAN",
                2984: "HPIDSADMIN",
                2985: "HPIDSAGENT",
                2986: "STONEFALLS",
                2987: "IDENTIFY",
                2988: "CLASSIFY",
                2989: "ZARKOV",
                2990: "BOSCAP",
                2991: "WKSTN-MON",
                2992: "ITB301",
                2993: "VERITAS VIS1",
                2994: "VERITAS VIS2",
                2995: "IDRS",
                2996: "vsixml",
                2997: "REBOL",
                2998: "Real Secure",
                2999: "RemoteWare Unassigned",
                3000: "RemoteWare Client",
                3001: "Phatbot Worm / Redwood Broker",
                3002: "RemoteWare Server",
                3003: "CGMS",
                3004: "Csoft Agent",
                3005: "Genius License Manager",
                3006: "Instant Internet Admin",
                3007: "Lotus Mail Tracking Agent Protocol",
                3008: "Midnight Technologies",
                3009: "PXC-NTFY",
                3010: "Telerate Workstation",
                3011: "Trusted Web",
                3012: "Trusted Web Client",
                3013: "Gilat Sky Surfer",
                3014: "Broker Service",
                3015: "NATI DSTP",
                3016: "Notify Server",
                3017: "Event Listener",
                3018: "Service Registry",
                3019: "Resource Manager",
                3020: "CIFS",
                3021: "AGRI Server",
                3022: "CSREGAGENT",
                3023: "magicnotes",
                3024: "NDS_SSO",
                3025: "Arepa Raft",
                3026: "AGRI Gateway",
                3027: "LiebDevMgmt_C",
                3028: "LiebDevMgmt_DM",
                3029: "LiebDevMgmt_A",
                3030: "Arepa Cas",
                3031: "AgentVU",
                3032: "Redwood Chat",
                3033: "PDB",
                3034: "Osmosis AEEA",
                3035: "FJSV gssagt",
                3036: "Hagel DUMP",
                3037: "HP SAN Mgmt",
                3038: "Santak UPS",
                3039: "Cogitate Inc.",
                3040: "Tomato Springs",
                3041: "di-traceware",
                3042: "journee",
                3043: "BRP",
                3045: "ResponseNet",
                3046: "di-ase",
                3047: "Fast Security HL Server",
                3048: "Sierra Net PC Trader",
                3049: "NSWS",
                3050: "gds_db",
                3051: "Galaxy Server",
                3052: "APCPCNS",
                3053: "dsom-server",
                3054: "AMT CNF PROT",
                3055: "Policy Server",
                3056: "CDL Server",
                3057: "GoAhead FldUp",
                3058: "videobeans",
                3059: "qsoft",
                3060: "interserver",
                3061: "cautcpd",
                3062: "ncacn-ip-tcp",
                3063: "ncadg-ip-udp",
                3065: "slinterbase",
                3066: "NETATTACHSDMP",
                3067: "W32.Korgo Worm / FJHPJP",
                3068: "ls3 Broadcast",
                3069: "ls3",
                3070: "MGXSWITCH",
                3075: "Orbix 2000 Locator",
                3076: "Orbix 2000 Config",
                3077: "Orbix 2000 Locator SSL",
                3078: "Orbix 2000 Locator SSL",
                3079: "LV Front Panel",
                3080: "stm_pproc",
                3081: "TL1-LV",
                3082: "TL1-RAW",
                3083: "TL1-TELNET",
                3084: "ITM-MCCS",
                3085: "PCIHReq",
                3086: "JDL-DBKitchen",
                3105: "Cardbox",
                3106: "Cardbox HTTP",
                3127: "W32.Mydoom.A virus",
                3128: "Squid HTTP Proxy / W32.Mydoom.B virus",
                3129: "Master's Paradise (Windows Trojan)",
                3130: "ICPv2",
                3131: "Net Book Mark",
                3141: "VMODEM",
                3142: "RDC WH EOS",
                3143: "Sea View",
                3144: "Tarantella",
                3145: "CSI-LFAP",
                3147: "RFIO",
                3148: "NetMike Game Administrator",
                3149: "NetMike Game Server",
                3150: "NetMike Assessor Administrator",
                3151: "NetMike Assessor",
                3180: "Millicent Broker Server",
                3181: "BMC Patrol Agent",
                3182: "BMC Patrol Rendezvous",
                3262: "NECP",
                3264: "cc:mail/lotus",
                3265: "Altav Tunnel",
                3266: "NS CFG Server",
                3267: "IBM Dial Out",
                3268: "Microsoft Global Catalog",
                3269: "Microsoft Global Catalog with LDAP/SSL",
                3270: "Verismart",
                3271: "CSoft Prev Port",
                3272: "Fujitsu User Manager",
                3273: "Simple Extensible Multiplexed Protocol",
                3274: "Ordinox Server",
                3275: "SAMD",
                3276: "Maxim ASICs",
                3277: "AWG Proxy",
                3278: "LKCM Server",
                3279: "admind",
                3280: "VS Server",
                3281: "SYSOPT",
                3282: "Datusorb",
                3283: "Net Assistant",
                3284: "4Talk",
                3285: "Plato",
                3286: "E-Net",
                3287: "DIRECTVDATA",
                3288: "COPS",
                3289: "ENPC",
                3290: "CAPS LOGISTICS TOOLKIT - LM",
                3291: "S A Holditch & Associates - LM",
                3292: "Cart O Rama",
                3293: "fg-fps",
                3294: "fg-gip",
                3295: "Dynamic IP Lookup",
                3296: "Rib License Manager",
                3297: "Cytel License Manager",
                3298: "Transview",
                3299: "pdrncs",
                3300: "bmc-patrol-agent",
                3301: "Unathorised use by SAP R/3",
                3302: "MCS Fastmail",
                3303: "OP Session Client",
                3304: "OP Session Server",
                3305: "ODETTE-FTP",
                3306: "MySQL",
                3307: "OP Session Proxy",
                3308: "TNS Server",
                3309: "TNS ADV",
                3310: "Dyna Access",
                3311: "MCNS Tel Ret",
                3312: "Application Management Server",
                3313: "Unify Object Broker",
                3314: "Unify Object Host",
                3315: "CDID",
                3316: "AICC/CMI",
                3317: "VSAI PORT",
                3318: "Swith to Swith Routing Information Protocol",
                3319: "SDT License Manager",
                3320: "Office Link 2000",
                3321: "VNSSTR",
                3325: "isi.edu",
                3326: "SFTU",
                3327: "BBARS",
                3328: "Eaglepoint License Manager",
                3329: "HP Device Disc",
                3330: "MCS Calypso ICF",
                3331: "MCS Messaging",
                3332: "MCS Mail Server",
                3333: "DEC Notes",
                3334: "Direct TV Webcasting",
                3335: "Direct TV Software Updates",
                3336: "Direct TV Tickers",
                3337: "Direct TV Data Catalog",
                3338: "OMF data b",
                3339: "OMF data l",
                3340: "OMF data m",
                3341: "OMF data h",
                3342: "WebTIE",
                3343: "MS Cluster Net",
                3344: "BNT Manager",
                3345: "Influence",
                3346: "Trnsprnt Proxy",
                3347: "Phoenix RPC",
                3348: "Pangolin Laser",
                3349: "Chevin Services",
                3350: "FINDVIATV",
                3351: "BTRIEVE",
                3352: "SSQL",
                3353: "FATPIPE",
                3354: "SUITJD",
                3355: "Hogle (proxy backdoor) / Ordinox Dbase",
                3356: "UPNOTIFYPS",
                3357: "Adtech Test IP",
                3358: "Mp Sys Rmsvr",
                3359: "WG NetForce",
                3360: "KV Server",
                3361: "KV Agent",
                3362: "DJ ILM",
                3363: "NATI Vi Server",
                3364: "Creative Server",
                3365: "Content Server",
                3366: "Creative Partner",
                3371: "ccm.jf.intel.com",
                3372: "Microsoft Distributed Transaction Coordinator (MSDTC) / TIP 2",
                3373: "Lavenir License Manager",
                3374: "Cluster Disc",
                3375: "VSNM Agent",
                3376: "CD Broker",
                3377: "Cogsys Network License Manager",
                3378: "WSICOPY",
                3379: "SOCORFS",
                3380: "SNS Channels",
                3381: "Geneous",
                3382: "Fujitsu Network Enhanced Antitheft function",
                3383: "Enterprise Software Products License Manager",
                3384: "Cluster Management Services",
                3385: "qnxnetman",
                3386: "GPRS Data",
                3387: "Back Room Net",
                3388: "CB Server",
                3389: "MS Terminal Server",
                3390: "Distributed Service Coordinator",
                3391: "SAVANT",
                3392: "EFI License Management",
                3393: "D2K Tapestry Client to Server",
                3394: "D2K Tapestry Server to Server",
                3395: "Dyna License Manager (Elam)",
                3396: "Printer Agent",
                3397: "Cloanto License Manager",
                3398: "Mercantile",
                3399: "CSMS",
                3400: "CSMS2",
                3401: "filecast",
                3410: "Backdoor.OptixPro.13",
                3421: "Bull Apprise portmapper",
                3454: "Apple Remote Access Protocol",
                3455: "RSVP Port",
                3456: "VAT default data",
                3457: "VAT default control",
                3458: "D3WinOsfi",
                3459: "TIP Integral",
                3460: "EDM Manger",
                3461: "EDM Stager",
                3462: "EDM STD Notify",
                3463: "EDM ADM Notify",
                3464: "EDM MGR Sync",
                3465: "EDM MGR Cntrl",
                3466: "WORKFLOW",
                3467: "RCST",
                3468: "TTCM Remote Controll",
                3469: "Pluribus",
                3470: "jt400",
                3471: "jt400-ssl",
                3535: "MS-LA",
                3563: "Watcom Debug",
                3572: "harlequin.co.uk",
                3672: "harlequinorb",
                3689: "Apple Digital Audio Access Protocol",
                3802: "VHD",
                3845: "V-ONE Single Port Proxy",
                3862: "GIGA-POCKET",
                3875: "PNBSCADA",
                3900: "Unidata UDT OS",
                3984: "MAPPER network node manager",
                3985: "MAPPER TCP/IP server",
                3986: "MAPPER workstation server",
                3987: "Centerline",
                4000: "Terabase",
                4001: "Cisco mgmt / NewOak",
                4002: "pxc-spvr-ft",
                4003: "pxc-splr-ft",
                4004: "pxc-roid",
                4005: "pxc-pin",
                4006: "pxc-spvr",
                4007: "pxc-splr",
                4008: "NetCheque accounting",
                4009: "Chimera HWM",
                4010: "Samsung Unidex",
                4011: "Alternate Service Boot",
                4012: "PDA Gate",
                4013: "ACL Manager",
                4014: "TAICLOCK",
                4015: "Talarian Mcast",
                4016: "Talarian Mcast",
                4017: "Talarian Mcast",
                4018: "Talarian Mcast",
                4019: "Talarian Mcast",
                4045: "nfs-lockd",
                4096: "BRE (Bridge Relay Element)",
                4097: "Patrol View",
                4098: "drmsfsd",
                4099: "DPCP",
                4132: "NUTS Daemon",
                4133: "NUTS Bootp Server",
                4134: "NIFTY-Serve HMI protocol",
                4141: "Workflow Server",
                4142: "Document Server",
                4143: "Document Replication",
                4144: "Compuserve pc windows",
                4160: "Jini Discovery",
                4199: "EIMS ADMIN",
                4299: "earth.path.net",
                4300: "Corel CCam",
                4321: "Remote Who Is",
                4333: "mini-sql server",
                4343: "UNICALL",
                4344: "VinaInstall",
                4345: "Macro 4 Network AS",
                4346: "ELAN LM",
                4347: "LAN Surveyor",
                4348: "ITOSE",
                4349: "File System Port Map",
                4350: "Net Device",
                4351: "PLCY Net Services",
                4353: "F5 iQuery",
                4397: "Phatbot Worm",
                4442: "Saris",
                4443: "Pharos",
                4444: "AdSubtract / NV Video default",
                4445: "UPNOTIFYP",
                4446: "N1-FWP",
                4447: "N1-RMGMT",
                4448: "ASC Licence Manager",
                4449: "PrivateWire",
                4450: "Camp",
                4451: "CTI System Msg",
                4452: "CTI Program Load",
                4453: "NSS Alert Manager",
                4454: "NSS Agent Manager",
                4455: "PR Chat User",
                4456: "PR Chat Server",
                4457: "PR Register",
                4500: "sae-urn",
                4501: "urn-x-cdchoice",
                4545: "WorldScores",
                4546: "SF License Manager (Sentinel)",
                4547: "Lanner License Manager",
                4557: "FAX transmission service",
                4559: "HylaFAX client-service protocol",
                4567: "TRAM",
                4568: "BMC Reporting",
                4600: "Piranha1",
                4601: "Piranha2",
                4661: "eDonkey2k",
                4662: "eDonkey2k",
                4663: "eDonkey",
                4665: "eDonkey2k",
                4672: "remote file access server",
                4675: "eMule",
                4711: "eMule",
                4751: "W32.Beagle.V trojan",
                4772: "eMule",
                4800: "Icona Instant Messenging System",
                4801: "Icona Web Embedded Chat",
                4802: "Icona License System Server",
                4820: "Backdoor.Tuxter",
                4827: "HTCP",
                4837: "Varadero-0",
                4838: "Varadero-1",
                4868: "Photon Relay",
                4869: "Photon Relay Debug",
                4885: "ABBS",
                4899: "RAdmin Win32 remote control",
                4983: "AT&T Intercom",
                5000: "UPnP / filmaker.com / Socket de Troie (Windows Trojan)",
                5001: "filmaker.com / Socket de Troie (Windows Trojan)",
                5002: "radio free ethernet",
                5003: "FileMaker Inc. - Proprietary transport",
                5004: "avt-profile-1",
                5005: "avt-profile-2",
                5006: "wsm server",
                5007: "wsm server ssl",
                5010: "TelepathStart",
                5011: "TelepathAttack",
                5020: "zenginkyo-1",
                5021: "zenginkyo-2",
                5042: "asnaacceler8db",
                5050: "Yahoo Messenger / multimedia conference control tool",
                5051: "ITA Agent",
                5052: "ITA Manager",
                5055: "UNOT",
                5060: "SIP",
                5069: "I/Net 2000-NPR",
                5071: "PowerSchool",
                5093: "Sentinel LM",
                5099: "SentLM Srv2Srv",
                5101: "Yahoo! Messenger",
                5145: "RMONITOR SECURE",
                5150: "Ascend Tunnel Management Protocol",
                5151: "ESRI SDE Instance",
                5152: "ESRI SDE Instance Discovery",
                5165: "ife_1corp",
                5190: "America-Online",
                5191: "AmericaOnline1",
                5192: "AmericaOnline2",
                5193: "AmericaOnline3",
                5200: "Targus AIB 1",
                5201: "Targus AIB 2",
                5202: "Targus TNTS 1",
                5203: "Targus TNTS 2",
                5222: "Jabber Server",
                5232: "SGI Distribution Graphics",
                5236: "padl2sim",
                5272: "PK",
                5300: "HA cluster heartbeat",
                5301: "HA cluster general services",
                5302: "HA cluster configuration",
                5303: "HA cluster probing",
                5304: "HA Cluster Commands",
                5305: "HA Cluster Test",
                5306: "Sun MC Group",
                5307: "SCO AIP",
                5308: "CFengine",
                5309: "J Printer",
                5310: "Outlaws",
                5311: "TM Login",
                5373: "W32.Gluber.B@mm",
                5400: "Excerpt Search / Blade Runner (Windows Trojan)",
                5401: "Excerpt Search Secure / Blade Runner (Windows Trojan)",
                5402: "MFTP / Blade Runner (Windows Trojan)",
                5403: "HPOMS-CI-LSTN",
                5404: "HPOMS-DPS-LSTN",
                5405: "NetSupport",
                5406: "Systemics Sox",
                5407: "Foresyte-Clear",
                5408: "Foresyte-Sec",
                5409: "Salient Data Server",
                5410: "Salient User Manager",
                5411: "ActNet",
                5412: "Continuus",
                5413: "WWIOTALK",
                5414: "StatusD",
                5415: "NS Server",
                5416: "SNS Gateway",
                5417: "SNS Agent",
                5418: "MCNTP",
                5419: "DJ-ICE",
                5420: "Cylink-C",
                5421: "Net Support 2",
                5422: "Salient MUX",
                5423: "VIRTUALUSER",
                5426: "DEVBASIC",
                5427: "SCO-PEER-TTA",
                5428: "TELACONSOLE",
                5429: "Billing and Accounting System Exchange",
                5430: "RADEC CORP",
                5431: "PARK AGENT",
                5432: "postgres database server",
                5435: "Data Tunneling Transceiver Linking (DTTL)",
                5454: "apc-tcp-udp-4",
                5455: "apc-tcp-udp-5",
                5456: "apc-tcp-udp-6",
                5461: "SILKMETER",
                5462: "TTL Publisher",
                5465: "NETOPS-BROKER",
                5490: "Squid HTTP Proxy",
                5500: "fcp-addr-srvr1",
                5501: "fcp-addr-srvr2",
                5502: "fcp-srvr-inst1",
                5503: "fcp-srvr-inst2",
                5504: "fcp-cics-gw1",
                5510: "ACE/Server Services",
                5520: "ACE/Server Services",
                5530: "ACE/Server Services",
                5540: "ACE/Server Services",
                5550: "ACE/Server Services / Xtcp 2.0x",
                5554: "Sasser Worm FTP backdoor / SGI ESP HTTP",
                5555: "Personal Agent / W32.Mimail.P@mm",
                5556: "Mtbd (mtb backup)",
                5559: "Enterprise Security Remote Install axent.com",
                5599: "Enterprise Security Remote Install",
                5600: "Enterprise Security Manager",
                5601: "Enterprise Security Agent",
                5602: "A1-MSC",
                5603: "A1-BS",
                5604: "A3-SDUNode",
                5605: "A4-SDUNode",
                5631: "pcANYWHEREdata",
                5632: "pcANYWHEREstat",
                5678: "LinkSys EtherFast Router Remote Administration / Remote Replication Agent Connection",
                5679: "Direct Cable Connect Manager",
                5680: "Canna (Japanese Input)",
                5713: "proshare conf audio",
                5714: "proshare conf video",
                5715: "proshare conf data",
                5716: "proshare conf request",
                5717: "proshare conf notify",
                5729: "Openmail User Agent Layer",
                5741: "IDA Discover Port 1",
                5742: "IDA Discover Port 2 / Wincrash (Windows Trojan)",
                5745: "fcopy-server",
                5746: "fcopys-server",
                5755: "OpenMail Desk Gateway server",
                5757: "OpenMail X.500 Directory Server",
                5766: "OpenMail NewMail Server",
                5767: "OpenMail Suer Agent Layer (Secure)",
                5768: "OpenMail CMTS Server",
                5771: "NetAgent",
                5800: "VNC Virtual Network Computing",
                5801: "VNC Virtual Network Computing",
                5813: "ICMPD",
                5859: "WHEREHOO",
                5882: "Y3k",
                5900: "VNC Virtual Network Computing",
                5901: "VNC Virtual Network Computing",
                5968: "mppolicy-v5",
                5969: "mppolicy-mgr",
                5977: "NCD preferences TCP port",
                5978: "NCD diagnostic TCP port",
                5979: "NCD configuration TCP port",
                5980: "VNC Virtual Network Computing",
                5981: "VNC Virtual Network Computing",
                5987: "Solaris Web Enterprise Management RMI",
                5997: "NCD preferences telnet port",
                5998: "NCD diagnostic telnet port",
                5999: "CVSup",
                6000: "X-Windows / W32.LoveGate.ak virus",
                6001: "Cisco mgmt",
                6003: "Half-Life WON server",
                6063: "X Windows System mit.edu",
                6064: "NDL-AHP-SVC",
                6065: "WinPharaoh",
                6066: "EWCTSP",
                6067: "SRB",
                6068: "GSMP",
                6069: "TRIP",
                6070: "Messageasap",
                6071: "SSDTP",
                6072: "DIAGNOSE-PROC",
                6073: "DirectPlay8",
                6100: "SynchroNet-db",
                6101: "SynchroNet-rtc",
                6102: "SynchroNet-upd",
                6103: "RETS",
                6104: "DBDB",
                6105: "Prima Server",
                6106: "MPS Server",
                6107: "ETC Control",
                6108: "Sercomm-SCAdmin",
                6109: "GLOBECAST-ID",
                6110: "HP SoftBench CM",
                6111: "HP SoftBench Sub-Process Control",
                6112: "dtspcd / Blizzard Battlenet",
                6123: "Backup Express",
                6129: "DameWare",
                6141: "Meta Corporation License Manager",
                6142: "Aspen Technology License Manager",
                6143: "Watershed License Manager",
                6144: "StatSci License Manager - 1",
                6145: "StatSci License Manager - 2",
                6146: "Lone Wolf Systems License Manager",
                6147: "Montage License Manager",
                6148: "Ricardo North America License Manager",
                6149: "tal-pod",
                6253: "CRIP",
                6321: "Empress Software Connectivity Server 1",
                6322: "Empress Software Connectivity Server 2",
                6346: "Gnutella/Bearshare file sharing Application",
                6348: "Limewire P2P",
                6389: "clariion-evr01",
                6400: "saegatesoftware.com",
                6401: "saegatesoftware.com",
                6402: "saegatesoftware.com",
                6403: "saegatesoftware.com",
                6404: "saegatesoftware.com",
                6405: "saegatesoftware.com",
                6406: "saegatesoftware.com",
                6407: "saegatesoftware.com",
                6408: "saegatesoftware.com",
                6409: "saegatesoftware.com",
                6410: "saegatesoftware.com",
                6455: "SKIP Certificate Receive",
                6456: "SKIP Certificate Send",
                6471: "LVision License Manager",
                6500: "BoKS Master",
                6501: "BoKS Servc",
                6502: "BoKS Servm",
                6503: "BoKS Clntd",
                6505: "BoKS Admin Private Port",
                6506: "BoKS Admin Public Port",
                6507: "BoKS Dir Server Private Port",
                6508: "BoKS Dir Server Public Port",
                6547: "apc-tcp-udp-1",
                6548: "apc-tcp-udp-2",
                6549: "apc-tcp-udp-3",
                6550: "fg-sysupdate",
                6558: "xdsxdm",
                6588: "AnalogX Web Proxy",
                6665: "Internet Relay Chat",
                6666: "IRC / Windows Media Unicast Service",
                6667: "IRC",
                6668: "IRC",
                6669: "IRC",
                6670: "Vocaltec Global Online Directory / Deep Throat 2 (Windows Trojan)",
                6672: "vision_server",
                6673: "vision_elmd",
                6699: "Napster",
                6700: "Napster / Carracho (server)",
                6701: "Napster / Carracho (server)",
                6711: "SubSeven (Windows Trojan)",
                6723: "DDOS communication TCP",
                6767: "BMC PERFORM AGENT",
                6768: "BMC PERFORM MGRD",
                6776: "SubSeven/BackDoor-G (Windows Trojan)",
                6777: "W32.Beagle.A trojan",
                6789: "IBM DB2",
                6790: "HNMP / IBM DB2",
                6831: "ambit-lm",
                6841: "Netmo Default",
                6842: "Netmo HTTP",
                6850: "ICCRUSHMORE",
                6881: "BitTorrent Network",
                6888: "MUSE",
                6891: "MS Messenger file transfer",
                6901: "MS Messenger voice calls",
                6961: "JMACT3",
                6962: "jmevt2",
                6963: "swismgr1",
                6964: "swismgr2",
                6965: "swistrap",
                6966: "swispol",
                6969: "acmsoda",
                6998: "IATP-highPri",
                6999: "IATP-normalPri",
                7000: "IRC / file server itself",
                7001: "WebLogic Server / Callbacks to cache managers",
                7002: "WebLogic Server (SSL) / Half-Life Auth Server / Users & groups database",
                7003: "volume location database",
                7004: "AFS/Kerberos authentication service",
                7005: "volume managment server",
                7006: "error interpretation service",
                7007: "Windows Media Services / basic overseer process",
                7008: "server-to-server updater",
                7009: "remote cache manager service",
                7010: "onlinet uninterruptable power supplies",
                7011: "Talon Discovery Port",
                7012: "Talon Engine",
                7013: "Microtalon Discovery",
                7014: "Microtalon Communications",
                7015: "Talon Webserver",
                7020: "DP Serve",
                7021: "DP Serve Admin",
                7070: "ARCP",
                7099: "lazy-ptop",
                7100: "X Font Service",
                7121: "Virtual Prototypes License Manager",
                7141: "vnet.ibm.com",
                7161: "Catalyst",
                7174: "Clutild",
                7200: "FODMS FLIP",
                7201: "DLIP",
                7323: "3.11 Remote Administration",
                7326: "Internet Citizen's Band",
                7390: "The Swiss Exchange swx.ch",
                7395: "winqedit",
                7426: "OpenView DM Postmaster Manager",
                7427: "OpenView DM Event Agent Manager",
                7428: "OpenView DM Log Agent Manager",
                7429: "OpenView DM rqt communication",
                7430: "OpenView DM xmpv7 api pipe",
                7431: "OpenView DM ovc/xmpv3 api pipe",
                7437: "Faximum",
                7491: "telops-lmd",
                7511: "pafec-lm",
                7544: "FlowAnalyzer DisplayServer",
                7545: "FlowAnalyzer UtilityServer",
                7566: "VSI Omega",
                7570: "Aries Kfinder",
                7588: "Sun License Manager",
                7597: "TROJAN WORM",
                7633: "PMDF Management",
                7640: "CUSeeMe",
                7777: "Oracle App server / cbt",
                7778: "Windows Media Services / Interwise",
                7781: "accu-lmgr",
                7786: "MINIVEND",
                7932: "Tier 2 Data Resource Manager",
                7933: "Tier 2 Business Rules Manager",
                7967: "Supercell",
                7979: "Micromuse-ncps",
                7980: "Quest Vista",
                7999: "iRDMI2",
                8000: "HTTP/iRDMI",
                8001: "HTTP/VCOM Tunnel",
                8002: "HTTP/Teradata ORDBMS",
                8007: "Apache JServ Protocol",
                8008: "HTTP Alternate",
                8009: "Apache JServ Protocol",
                8010: "Wingate HTTP Proxy",
                8032: "ProEd",
                8033: "MindPrint",
                8080: "HTTP / HTTP Proxy",
                8081: "HTTP / HTTP Proxy",
                8082: "BlackICE Capture",
                8129: "Snapstream PVS Server",
                8130: "INDIGO-VRMI",
                8131: "INDIGO-VBCP",
                8160: "Patrol",
                8161: "Patrol SNMP",
                8181: "IPSwitch IMail / Monitor",
                8200: "TRIVNET",
                8201: "TRIVNET",
                8204: "LM Perfworks",
                8205: "LM Instmgr",
                8206: "LM Dta",
                8207: "LM SServer",
                8208: "LM Webwatcher",
                8351: "Server Find",
                8376: "Cruise ENUM",
                8377: "Cruise SWROUTE",
                8378: "Cruise CONFIG",
                8379: "Cruise DIAGS",
                8380: "Cruise UPDATE",
                8383: "Web Email",
                8400: "cvd",
                8401: "sabarsd",
                8402: "abarsd",
                8403: "admind",
                8431: "Micro PC-Cilin",
                8450: "npmp",
                8473: "Virtual Point to Point",
                8484: "Ipswitch IMail",
                8554: "RTSP Alternate (see port 554)",
                8733: "iBus",
                8763: "MC-APPSERVER",
                8764: "OPENQUEUE",
                8765: "Ultraseek HTTP",
                8804: "truecm",
                8866: "W32.Beagle.B trojan",
                8880: "CDDBP",
                8888: "NewsEDGE server TCP / AnswerBook2",
                8889: "Desktop Data TCP 1",
                8890: "Desktop Data TCP 2",
                8891: "Desktop Data TCP 3: NESS application",
                8892: "Desktop Data TCP 4: FARM product",
                8893: "Desktop Data TCP 5: NewsEDGE/Web application",
                8894: "Desktop Data TCP 6: COAL application",
                8900: "JMB-CDS 1",
                8901: "JMB-CDS 2",
                8967: "Win32/Dabber (Windows worm)",
                8999: "Firewall",
                9000: "CSlistener",
                9001: "cisco-xremote",
                9090: "WebSM",
                9100: "HP JetDirect",
                9160: "NetLOCK1",
                9161: "NetLOCK2",
                9162: "NetLOCK3",
                9163: "NetLOCK4",
                9164: "NetLOCK5",
                9200: "WAP connectionless session service",
                9201: "WAP session service",
                9202: "WAP secure connectionless session service",
                9203: "WAP secure session service",
                9204: "WAP vCard",
                9205: "WAP vCal",
                9206: "WAP vCard Secure",
                9207: "WAP vCal Secure",
                9273: "BackGate (Windows rootkit)",
                9274: "BackGate (Windows rootkit)",
                9275: "BackGate (Windows rootkit)",
                9276: "BackGate (Windows rootkit)",
                9277: "BackGate (Windows rootkit)",
                9278: "BackGate (Windows rootkit)",
                9280: "HP JetDirect Embedded Web Server",
                9290: "HP JetDirect",
                9291: "HP JetDirect",
                9292: "HP JetDirect",
                9321: "guibase",
                9343: "MpIdcMgr",
                9344: "Mphlpdmc",
                9374: "fjdmimgr",
                9396: "fjinvmgr",
                9397: "MpIdcAgt",
                9400: "InCommand",
                9500: "ismserver",
                9535: "Remote man server",
                9537: "Remote man server, testing",
                9594: "Message System",
                9595: "Ping Discovery Service",
                9600: "MICROMUSE-NCPW",
                9753: "rasadv",
                9876: "Session Director",
                9888: "CYBORG Systems",
                9898: "MonkeyCom / Win32/Dabber (Windows worm)",
                9899: "SCTP TUNNELING",
                9900: "IUA",
                9909: "domaintime",
                9950: "APCPCPLUSWIN1",
                9951: "APCPCPLUSWIN2",
                9952: "APCPCPLUSWIN3",
                9992: "Palace",
                9993: "Palace",
                9994: "Palace",
                9995: "Palace",
                9996: "Sasser Worm shell / Palace",
                9997: "Palace",
                9998: "Distinct32",
                9999: "distinct / Win32/Dabber (Windows worm)",
                10000: "Webmin / Network Data Management Protocol/ Dumaru.Y (Windows trojan)",
                10001: "queue",
                10002: "poker",
                10003: "gateway",
                10004: "remp",
                10005: "Secure telnet",
                10007: "MVS Capacity",
                10012: "qmaster",
                10080: "Amanda / MyDoom.B (Windows trojan)",
                10082: "Amanda Indexing",
                10083: "Amanda Tape Indexing",
                10113: "NetIQ Endpoint",
                10114: "NetIQ Qcheck",
                10115: "Ganymede Endpoint",
                10128: "BMC-PERFORM-SERVICE DAEMON",
                10202: "Computer Associate License Manager",
                10203: "Computer Associate License Manager",
                10204: "Computer Associate License Manager",
                10288: "Blocks",
                10520: "Acid Shivers (Windows Trojan)",
                11000: "IRISA",
                11001: "Metasys",
                11111: "Viral Computing Environment (VCE)",
                11117: "W32.Beagle.L trojan / URBISNET",
                11367: "ATM UHAS",
                11523: "AOL / AdSubtract AOL Proxy",
                11720: "h323 Call Signal Alternate",
                11722: "RK Test",
                12000: "IBM Enterprise Extender SNA XID Exchange",
                12001: "IBM Enterprise Extender SNA COS Network Priority",
                12002: "IBM Enterprise Extender SNA COS High Priority",
                12003: "IBM Enterprise Extender SNA COS Medium Priority",
                12004: "IBM Enterprise Extender SNA COS Low Priority",
                12172: "HiveP",
                12345: "Netbus (Windows Trojan)",
                12346: "NetBus (Windows Trojan)",
                12348: "BioNet (Windows Trojan)",
                12349: "BioNet (Windows Trojan)",
                12361: "Whack-a-mole (Windows Trojan)",
                12362: "Whack-a-mole (Windows Trojan)",
                12753: "tsaf port",
                12754: "DDOS communication TCP",
                13160: "I-ZIPQD",
                13223: "PowWow Client",
                13224: "PowWow Server",
                13326: "game",
                13720: "BPRD Protocol (VERITAS NetBackup)",
                13721: "BPBRM Protocol (VERITAS NetBackup)",
                13722: "BP Java MSVC Protocol",
                13782: "VERITAS NetBackup",
                13783: "VOPIED Protnocol",
                13818: "DSMCC Config",
                13819: "DSMCC Session Messages",
                13820: "DSMCC Pass-Thru Messages",
                13821: "DSMCC Download Protocol",
                13822: "DSMCC Channel Change Protocol",
                14001: "ITU SCCP (SS7)",
                14237: "Palm Network Hotsync",
                14247: "Mitglieder.H trojan",
                15104: "DDOS communication TCP",
                16360: "netserialext1",
                16361: "netserialext2",
                16367: "netserialext3",
                16368: "netserialext4",
                16660: "Stacheldraht distributed attack tool client",
                16959: "Subseven DEFCON8 2.1 backdoor remote access tool",
                16991: "INTEL-RCI-MP",
                17007: "isode-dua",
                17219: "Chipper",
                17300: "Kuang2 (Windows trojan)",
                17569: "Infector",
                17990: "Worldspan gateway",
                18000: "Beckman Instruments Inc.",
                18181: "OPSEC CVP",
                18182: "OPSEC UFP",
                18183: "OPSEC SAM",
                18184: "OPSEC LEA",
                18185: "OPSEC OMI",
                18187: "OPSEC ELA",
                18463: "AC Cluster",
                18753: "Shaft distributed attack tool handler agent",
                18888: "APCNECMP",
                19216: "BackGate (Windows rootkit)",
                19283: "Key Server for SASSAFRAS",
                19315: "Key Shadow for SASSAFRAS",
                19410: "hp-sco",
                19411: "hp-sca",
                19412: "HP-SESSMON",
                19541: "JCP Client",
                20000: "DNP",
                20005: "xcept4 (German Telekom's CEPT videotext service)",
                20031: "BakBone NetVault",
                20034: "NetBus 2 Pro (Windows Trojan)",
                20432: "Shaft distributed attack client",
                20670: "Track",
                20742: "Mitglieder.E trojan",
                20999: "At Hand MMP",
                21554: "Girlfriend (Windows Trojan)",
                21590: "VoFR Gateway",
                21845: "webphone",
                21846: "NetSpeak Corp. Directory Services",
                21847: "NetSpeak Corp. Connection Services",
                21848: "NetSpeak Corp. Automatic Call Distribution",
                21849: "NetSpeak Corp. Credit Processing System",
                22000: "SNAPenetIO",
                22001: "OptoControl",
                22156: "Phatbot Worm",
                22273: "wnn6",
                22289: "Wnn6 (Chinese Input)",
                22305: "Wnn6 (Korean Input)",
                22321: "Wnn6 (Taiwanese Input)",
                22555: "Vocaltec Web Conference",
                22800: "Telerate Information Platform LAN",
                22951: "Telerate Information Platform WAN",
                23005: "W32.HLLW.Nettrash",
                23006: "W32.HLLW.Nettrash",
                23432: "Asylum",
                23476: "Donald Dick",
                23477: "Donald Dick",
                23485: "Shareasa file sharing",
                24000: "med-ltp",
                24001: "med-fsp-rx",
                24002: "med-fsp-tx",
                24003: "med-supp",
                24004: "med-ovw",
                24005: "med-ci",
                24006: "med-net-svc",
                24386: "Intel RCI",
                24554: "BINKP",
                25000: "icl-twobase1",
                25001: "icl-twobase2",
                25002: "icl-twobase3",
                25003: "icl-twobase4",
                25004: "icl-twobase5",
                25005: "icl-twobase6",
                25006: "icl-twobase7",
                25007: "icl-twobase8",
                25008: "icl-twobase9",
                25009: "icl-twobase10",
                25555: "Mitglieder.D trojan",
                25793: "Vocaltec Address Server",
                25867: "WebCam32 Admin",
                26000: "quake",
                26208: "wnn6-ds",
                26274: "Delta Source (Windows Trojan)",
                27347: "SubSeven / Linux.Ramen.Worm (RedHat Linux)",
                27374: "SubSeven / Linux.Ramen.Worm (RedHat Linux)",
                27665: "Trinoo distributed attack tool Master server control port",
                27999: "TW Authentication/Key Distribution and",
                30100: "Netsphere (Windows Trojan)",
                30101: "Netsphere (Windows Trojan)",
                30102: "Netsphere (Windows Trojan)",
                30999: "Kuang",
                31337: "BO2K",
                31785: "Hack-A-Tack (Windows Trojan)",
                31787: "Hack-A-Tack (Windows Trojan)",
                31788: "Hack-A-Tack (Windows Trojan)",
                31789: "Hack-A-Tack (Windows Trojan)",
                31791: "Hack-A-Tack (Windows Trojan)",
                32000: "XtraMail v1.11",
                32768: "Filenet TMS",
                32769: "Filenet RPC",
                32770: "Filenet NCH",
                32771: "Solaris RPC",
                32772: "Solaris RPC",
                32773: "Solaris RPC",
                32774: "Solaris RPC",
                32775: "Solaris RPC",
                32776: "Solaris RPC",
                32777: "Solaris RPC",
                32780: "RPC",
                33434: "traceroute use",
                34324: "Big Gluck (Windows Trojan)",
                36865: "KastenX Pipe",
                40421: "Master's Paradise (Windows Trojan)",
                40422: "Master's Paradise (Windows Trojan)",
                40423: "Master's Paradise (Windows Trojan)",
                40426: "Master's Paradise (Windows Trojan)",
                40841: "CSCP",
                42424: "ASP.NET Session State",
                43118: "Reachout",
                43188: "Reachout",
                44333: "Kerio WinRoute Firewall Administration",
                44334: "Kerio Personal Firewall Administration",
                44337: "Kerio MailServer Administration",
                44444: "Prosiak",
                44818: "Rockwell Encapsulation",
                45092: "BackGate (Windows rootkit)",
                45678: "EBA PRISE",
                45966: "SSRServerMgr",
                47262: "Delta Source (Windows Trojan)",
                47557: "Databeam Corporation",
                47624: "Direct Play Server",
                47806: "ALC Protocol",
                47808: "Building Automation and Control Networks",
                48000: "Nimbus Controller",
                48001: "Nimbus Spooler",
                48002: "Nimbus Hub",
                48003: "Nimbus Gateway",
                49400: "Compaq Insight Manager",
                49401: "Compaq Insight Manager",
                50300: "O&O Defrag",
                51515: "Microsoft Operations Manager MOM-Clear",
                52673: "Stickies",
                54283: "SubSeven",
                54320: "Orifice 2000 (TCP)",
                54321: "Orifice 2000 (TCP)",
                60000: "DeepThroat",
                65000: "distributed attack tool / Devil (Windows Trojan)",
                65301: "pcAnywhere-def",
                65506: "PhatBot, Agobot, Gaobot (Windows trojans)",
            }

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
            ####################################################################
            # neuer Tab für Netzwerkkarten-Daten
            ####################################################################

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
                command=self.start_scan_ps,
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

    ####################################################################
    # Start Methoden Netzwerkkarten-Daten
    ####################################################################

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

    ####################################################################
    # Start Methoden externe IP
    ####################################################################

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

    ####################################################################
    # Ende Methoden externe IP
    ####################################################################

    ####################################################################
    # Start Methoden Ping-Tab
    ####################################################################

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

    def update_ip_entry_ping(self, event):
        """Aktualisiert das IP-Adressfeld im Ping-Tab mit dem ausgewählten Eintrag der Combobox."""
        selected_address = self.combobox_test_addresses_ping.get()
        self.entry_ping_ip.delete(0, ctk.END)
        self.entry_ping_ip.insert(0, selected_address)

    ####################################################################
    # Ende Methoden Ping-Tab
    ####################################################################

    ####################################################################
    # Start Methoden Tracert-Tab
    ####################################################################
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

    ####################################################################
    # Ende Methoden Tracert-Tab
    ####################################################################

    ####################################################################
    # Start Methoden nslookup-Tab
    ####################################################################

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

    ####################################################################
    # Ende Methoden nslookup-Tab
    ####################################################################

    ####################################################################
    # Start Methoden Speedtest-Tab
    ####################################################################

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

    ####################################################################
    # Ende Methoden Speedtest-Tab
    ####################################################################

    ####################################################################
    # Start Methoden Porttest-Tab
    ####################################################################

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

    ####################################################################
    # Ende Methoden Porttest-Tab
    ####################################################################

    ####################################################################
    # Start Methoden IP-Scan-Tab
    ####################################################################

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

    ####################################################################
    # Ende Methoden IP-Scan-Tab
    ####################################################################

    ####################################################################
    # Start Methoden Port-Scan-Tab
    ####################################################################
    def start_scan_ps(self):
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
                self.table_ps.insert(
                    "", "end", values=(port_ps, self.tcp_ports[port_ps])
                )

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
            self.action_frame_ps,
            text="Scan",
            command=self.start_scan_ps,
            corner_radius=20,
        )
        self.scan_button_ps.pack(pady=5)

    ####################################################################
    # Ende Methoden Port-Scan-Tab
    ####################################################################


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
