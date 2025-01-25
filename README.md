# Network Tools GUI

Dieses Projekt ist eine grafische Benutzeroberfläche (GUI) für Netzwerk-Tools, die mit Python und der `tkinter`-Bibliothek erstellt wurde. Es bietet Funktionen zur Verwaltung von Netzwerkkarten, zum Abrufen der öffentlichen IP-Adresse und zum Ausführen von Ping-Befehlen. Das Programm ist für Windows-Systeme entwickelt und erfordert Administratorrechte, um Netzwerkeinstellungen zu ändern.

---

## Funktionen

### 1. **Netzwerkkarten-Verwaltung**
   - **Netzwerkkarten anzeigen:** Zeigt alle aktiven Netzwerkkarten und deren aktuelle IP-Konfiguration (IP-Adresse, Subnetzmaske, Gateway, DNS-Server) an.
   - **DHCP/Statische IP:** Ermöglicht das Umschalten zwischen DHCP und statischer IP-Konfiguration.
   - **Einstellungen übernehmen:** Übernimmt die geänderten Einstellungen für die ausgewählte Netzwerkkarte.
   - **Profile speichern und laden:** Speichert die aktuelle Netzwerkkonfiguration unter einem Profilnamen und lädt gespeicherte Profile.

### 2. **Externe IP-Adresse**
   - **Öffentliche IP anzeigen:** Ruft die öffentliche IP-Adresse des Benutzers über eine externe API (`api.ipify.org`) ab und zeigt sie an.

### 3. **Ping-Tool**
   - **Ping ausführen:** Führt einen Ping-Befehl für eine angegebene IP-Adresse oder einen Hostnamen aus.
   - **Echtzeit-Ausgabe:** Zeigt die Ping-Ausgabe in Echtzeit in einer Textbox an.
   - **Befehlsverlauf:** Speichert die zuletzt ausgeführten Befehle und ermöglicht das erneute Ausführen.
   - **Prozess stoppen:** Stoppt den aktuellen Ping-Prozess.

---

## Voraussetzungen

- **Betriebssystem:** Windows
- **Python-Version:** 3.x
- **Erforderliche Bibliotheken:**
  - `tkinter` (Standardbibliothek)
  - `wmi`
  - `requests`

Die erforderlichen Bibliotheken können mit folgendem Befehl installiert werden:

```bash
pip install wmi requests
```

---

## Installation

1. **Repository klonen:**

   ```bash
   git clone https://github.com/dein-benutzername/network-tools-gui.git
   cd network-tools-gui
   ```

2. **Programm ausführen:**

   Führe die Datei `network_tools.py` mit Python aus:

   ```bash
   python network_tools.py
   ```

   **Hinweis:** Das Programm muss mit Administratorrechten ausgeführt werden. Wenn es ohne Administratorrechte gestartet wird, wird es automatisch neu gestartet und fordert die erforderlichen Berechtigungen an.

---

## Verwendung

### 1. **Netzwerkkarten-Verwaltung**
   - Wähle eine Netzwerkkarte aus dem Dropdown-Menü aus.
   - Wechsle zwischen DHCP und statischer IP-Konfiguration.
   - Gib bei statischer IP die gewünschte IP-Adresse, Subnetzmaske, Gateway und DNS-Server ein.
   - Klicke auf **Übernehmen**, um die Einstellungen zu speichern.

### 2. **Externe IP-Adresse**
   - Klicke auf **Öffentliche IP anzeigen**, um die öffentliche IP-Adresse abzurufen und anzuzeigen.

### 3. **Ping-Tool**
   - Gib eine IP-Adresse oder einen Hostnamen ein (z. B. `ping 8.8.8.8`).
   - Klicke auf **Senden**, um den Ping-Befehl auszuführen.
   - Die Ausgabe wird in Echtzeit in der Textbox angezeigt.
   - Verwende die Pfeiltasten (↑/↓), um durch den Befehlsverlauf zu navigieren.
   - Klicke auf **Abbrechen**, um den aktuellen Ping-Prozess zu stoppen.

---

## Screenshots

### Netzwerkkarten-Verwaltung
![Netzwerkkarten-Verwaltung](screenshots/network_interfaces.png)

### Externe IP-Adresse
![Externe IP-Adresse](screenshots/external_ip.png)

### Ping-Tool
![Ping-Tool](screenshots/ping_tool.png)

---

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Weitere Informationen findest du in der [LICENSE](LICENSE)-Datei.

---

## Beitrag

Falls du Verbesserungsvorschläge hast oder einen Fehler gefunden hast, erstelle bitte ein [Issue](https://github.com/dein-benutzername/network-tools-gui/issues) oder sende einen [Pull Request](https://github.com/dein-benutzername/network-tools-gui/pulls).

---

## Kontakt

Bei Fragen oder Anregungen kannst du mich gerne kontaktieren:

- **E-Mail:** deine-email@example.com
- **GitHub:** [dein-benutzername](https://github.com/dein-benutzername)

---

Viel Spaß mit dem Network Tools GUI! 😊
