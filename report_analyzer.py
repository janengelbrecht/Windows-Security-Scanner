import sys
import json
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QPushButton, QLabel, QTextBrowser, QHBoxLayout, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class SecurityReportAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSec Pro - Remediation & Analysis Analyzer")
        self.resize(1000, 800)
        self.report_data = None
        
        # Komplet base af specifikke trin-for-trin vejledninger baseret på check_id
        self.known_guides = {
            # Hardware
            "tpm": "1. Genstart computeren og tryk på tasten for at åbne BIOS/UEFI (ofte F2, Del eller F12).\n2. Naviger til sikkerhedsindstillingerne (Security/Advanced).\n3. Aktiver TPM (kan hedde fTPM på AMD eller PTT på Intel systemer).\n4. Gem ændringerne og genstart.",
            "secure_boot": "1. Genstart computeren og gå ind i BIOS/UEFI.\n2. Find menuen 'Boot' eller 'Security'.\n3. Sæt 'Secure Boot' til 'Enabled'.\n4. Gem ændringerne og afslut.",
            "bitlocker": "1. Tryk på Start, søg efter 'Kontrolpanel' og åbn det.\n2. Gå til 'System og sikkerhed' -> 'BitLocker-drevkryptering'.\n3. Klik på 'Slå BitLocker til' ud for systemdrevet.\n4. Følg guiden for at gemme din genoprettelsesnøgle og starte krypteringen.",
            "vbs": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.\n2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> System -> Device Guard.\n3. Dobbeltklik på 'Slå virtualiseringsbaseret sikkerhed til'.\n4. Vælg 'Aktiveret' og klik OK. Genstart computeren.",
            "memory_integrity": "1. Tryk på Start og åbn 'Windows Sikkerhed'.\n2. Klik på 'Enhedssikkerhed'.\n3. Vælg 'Nulstillingsisolation' (Core isolation) detaljer.\n4. Slå 'Hukommelsesintegritet' TIL og genstart computeren.",
            "credential_guard": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.\n2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> System -> Device Guard.\n3. Dobbeltklik på 'Slå virtualiseringsbaseret sikkerhed til'.\n4. Vælg 'Aktiveret' og under indstillinger for Credential Guard, vælg 'Enabled med UEFI lock'. Klik OK.",
            "dma_protection": "1. Genstart computeren og gå ind i BIOS/UEFI.\n2. Find indstillinger for virtualisering (VT-d for Intel, AMD-Vi for AMD).\n3. Aktiver Kernel DMA Protection eller IOMMU.\n4. Gem og afslut.",
            
            # Identity
            "lsa_protection": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n3. Højreklik, vælg Ny -> DWORD-værdi (32-bit) og kald den 'RunAsPPL'.\n4. Sæt Værdidata til 1, klik OK og genstart computeren.",
            "wdigest": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\n3. Højreklik, opret eller ret DWORD-værdien 'UseLogonCredential'.\n4. Sæt Værdidata til 0 og klik OK.",
            "guest_disabled": "1. Højreklik på Start og vælg 'Computeradministration' (compmgmt.msc).\n2. Gå til 'Lokale brugere og grupper' -> 'Brugere'.\n3. Højreklik på kontoen 'Gæst' (Guest) og vælg Egenskaber.\n4. Sæt flueben i 'Kontoen er deaktiveret' og klik OK.",
            "lm_hash": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.\n3. Dobbeltklik på 'Netværkssikkerhed: Gem ikke LAN Manager-hashværdi af næste adgangskodeændring'.\n4. Vælg 'Aktiveret' og klik OK.",
            "cached_logons": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.\n3. Dobbeltklik på 'Interaktivt logon: Antal tidligere logons til cache...'.\n4. Sæt værdien til 2 (eller lavere) og klik OK.",
            "blank_passwords": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.\n3. Dobbeltklik på 'Konti: Begræns brugen af tomme adgangskoder til konsollogon'.\n4. Vælg 'Aktiveret' og klik OK.",
            "legal_notice": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.\n3. Udfyld en standardtekst i 'Interaktivt logon: Meddelelsestekst til brugere...'.\n4. Udfyld titlen i 'Interaktivt logon: Meddelelsestitel til brugere...'. Klik OK.",
            "admin_disabled": "1. Højreklik på Start og vælg 'Computeradministration' (compmgmt.msc).\n2. Gå til 'Lokale brugere og grupper' -> 'Brugere'.\n3. Højreklik på kontoen 'Administrator' og vælg Egenskaber.\n4. Sæt flueben i 'Kontoen er deaktiveret' og klik OK.",
            "laps_enabled": "1. Download og installer Microsoft LAPS (Local Administrator Password Solution).\n2. Konfigurer Group Policy Object (GPO) til at aktivere LAPS for klienten.\n3. Tildel rettigheder i Active Directory til at læse adgangskoderne.",
            "admin_count_safe": "1. Højreklik på Start og vælg 'Computeradministration' (compmgmt.msc).\n2. Gå til 'Lokale brugere og grupper' -> 'Grupper'.\n3. Dobbeltklik på 'Administratorer'.\n4. Fjern brugere/grupper der ikke strengt behøver administratorrettigheder, så der er maks 3 tilbage.",
            
            # Network
            "smb1_disabled": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.\n2. Kopiér og indsæt følgende kommando: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n3. Tryk Enter. Genstart computeren, når du bliver bedt om det.",
            "smb_signing": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\n3. Find eller opret DWORD 'RequireSecuritySignature'.\n4. Sæt værdien til 1 og klik OK.",
            "ntlmv2_only": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.\n3. Find 'Netværkssikkerhed: Godkendelsesniveau for LAN Manager'.\n4. Sæt den til 'Send kun NTLMv2-svar. Afvis LM og NTLM'. Klik OK.",
            "llmnr": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.\n2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> Netværk -> DNS-klient.\n3. Dobbeltklik på 'Deaktiver multicastnavnefortolkning'.\n4. Vælg 'Aktiveret' og klik OK.",
            "netbios": "1. Tryk Windows-tast + R, skriv 'ncpa.cpl' og tryk Enter.\n2. Højreklik på dit primære netværkskort og vælg Egenskaber.\n3. Dobbeltklik på 'Internet Protocol Version 4 (TCP/IPv4)' og klik på knappen 'Avanceret'.\n4. Under fanen WINS, vælg 'Deaktiver NetBIOS over TCP/IP'. Klik OK.",
            "rdp_nla": "1. Tryk Windows-tast + R, skriv 'sysdm.cpl' og tryk Enter.\n2. Gå til fanen 'Fjernadgang' (Remote).\n3. Under Fjernskrivebord, marker boksen 'Tillad kun forbindelser fra computere, der kører Fjernskrivebord med Godkendelse på netværksniveau'. Klik OK.",
            "ipv6_disabled": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\n3. Opret DWORD-værdien 'DisabledComponents'.\n4. Sæt værdien til 255 (Decimal) og klik OK.",
            "remote_registry": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.\n2. Find tjenesten 'Fjernregistreringsdatabase' (Remote Registry).\n3. Dobbeltklik på den og sæt Starttype til 'Deaktiveret'.\n4. Klik på 'Stop' hvis tjenesten kører, og derefter OK.",
            "wpad": "1. Tryk Windows-tast + I for at åbne Indstillinger.\n2. Gå til Netværk og internet -> Proxy.\n3. Slå funktionen 'Find automatisk indstillinger' FRA.",
            "icmp_redirects": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\n3. Find eller opret DWORD 'EnableICMPRedirect'.\n4. Sæt værdien til 0 og klik OK.",
            "firewall_domain": "1. Tryk Windows-tast + R, skriv 'wf.msc' og tryk Enter.\n2. Klik på 'Egenskaber for Windows Defender Firewall'.\n3. Under fanen 'Domæneprofil', sæt Firewalltilstand til 'Til (anbefales)'. Klik OK.",
            "firewall_private": "1. Tryk Windows-tast + R, skriv 'wf.msc' og tryk Enter.\n2. Klik på 'Egenskaber for Windows Defender Firewall'.\n3. Under fanen 'Privat profil', sæt Firewalltilstand til 'Til (anbefales)'. Klik OK.",
            "firewall_public": "1. Tryk Windows-tast + R, skriv 'wf.msc' og tryk Enter.\n2. Klik på 'Egenskaber for Windows Defender Firewall'.\n3. Under fanen 'Offentlig profil', sæt Firewalltilstand til 'Til (anbefales)'. Klik OK.",
            "risky_ports": "1. Åbn PowerShell som Administrator.\n2. Kør 'Get-NetTCPConnection -State Listen' for at finde porte som f.eks. 21, 23 eller 69.\n3. Kør 'Get-Process -Id [PID]' (PID fra forrige trin) for at se programmet.\n4. Afinstaller programmet eller deaktiver dets tjeneste i services.msc.",
            
            # Forensics
            "ps_script_logging": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.\n2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> Windows-komponenter -> Windows PowerShell.\n3. Dobbeltklik på 'Slå logføring af PowerShell-scriptblok til'.\n4. Vælg 'Aktiveret' og klik OK.",
            "ps_transcription": "1. I gpedit.msc, naviger til Windows PowerShell-mappen.\n2. Find og dobbeltklik på 'Slå PowerShell-transskription til'.\n3. Vælg 'Aktiveret'.\n4. Vælg eventuelt en output-mappe til logfilerne og klik OK.",
            "ps_module_logging": "1. I gpedit.msc, naviger til Windows PowerShell-mappen.\n2. Find og dobbeltklik på 'Slå modullogføring til'.\n3. Vælg 'Aktiveret'.\n4. Klik på 'Vis' ud for Modulnavne, skriv '*' for at logge alle moduler, og klik OK.",
            "cmd_auditing": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.\n2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> System -> Overvågning af procesoprettelse.\n3. Dobbeltklik på politikken, vælg 'Aktiveret'.\n4. Marker boksen, så kommandolinjen inkluderes. Klik OK.",
            "ps_v2_disabled": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.\n2. Kopiér og indsæt: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2\n3. Tryk Enter. Genstart systemet efterfølgende.",
            "ps_exec_policy": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.\n2. Skriv kommandoen: Set-ExecutionPolicy RemoteSigned\n3. Tryk Enter og bekræft ved at taste 'Y'.",
            "audit_logon": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Overvågningspolitik.\n3. Dobbeltklik på 'Overvåg logonhændelser'.\n4. Sæt flueben i både 'Succes' og 'Fejl'. Klik OK.",
            
            # OS & Services
            "uac": "1. Tryk på Start, skriv 'UAC' og tryk Enter for at åbne Kontrol af brugerkonti.\n2. Træk skyderen helt i top ('Giv altid besked, når...').\n3. Klik OK og bekræft handlingen.",
            "autorun": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\n3. Opret en ny DWORD-værdi (32-bit) og kald den 'NoDriveTypeAutoRun'.\n4. Sæt Værdidata til 255 (Decimal) og klik OK.",
            "fast_startup": "1. Tryk Windows-tast + R, skriv 'powercfg.cpl' og tryk Enter.\n2. Klik på 'Vælg, hvad tænd/sluk-knapperne gør' til venstre.\n3. Klik på 'Rediger indstillinger, der aktuelt ikke er tilgængelige'.\n4. Fjern fluebenet ved 'Aktivér hurtig start (anbefales)'. Klik OK.",
            "clear_pagefile": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.\n2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.\n3. Dobbeltklik på 'Nedlukning: Ryd sidefil til virtuel hukommelse'.\n4. Vælg 'Aktiveret' og klik OK.",
            "sticky_keys": "1. Tryk på Shift-tasten 5 gange hurtigt efter hinanden for at udløse Træge Taster-boksen.\n2. Klik på linket i pop-up vinduet for at åbne Indstillinger for tastaturet.\n3. Slå genvejstasterne FRA for både 'Træge taster' (Sticky Keys) og 'Filtertaster'.",
            "smartscreen": "1. Tryk på Start og åbn 'Windows Sikkerhed'.\n2. Klik på 'App- og browserstyring'.\n3. Klik på 'Omdømmebaserede beskyttelsesindstillinger'.\n4. Slå 'Kontrollér apps og filer' (SmartScreen for Windows) TIL.",
            "telemetry": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.\n2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> Windows-komponenter -> Dataindsamling.\n3. Dobbeltklik på 'Tillad telemetri' (eller Diagnosedata).\n4. Vælg 'Aktiveret' og sæt niveauet til 'Sikkerhed' (0). Klik OK.",
            "crash_dump": "1. Tryk Windows-tast + R, skriv 'sysdm.cpl' og tryk Enter.\n2. Gå til fanen 'Avanceret'.\n3. Under 'Start og genoprettelse', klik på 'Indstillinger'.\n4. Under 'Skriv fejlfindingsoplysninger', vælg '(Ingen)' fra dropdown-menuen. Klik OK.",
            "print_spooler": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.\n2. Find tjenesten 'Print Spooler' (Printkø).\n3. Dobbeltklik og skift Starttype til 'Deaktiveret'.\n4. Klik på 'Stop' og derefter OK.",
            "xbox_services": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.\n2. Find alle tjenester der starter med 'Xbox' (f.eks. Xbox Live Auth Manager).\n3. Dobbeltklik på hver af dem og sæt Starttype til 'Deaktiveret'.\n4. Klik 'Stop' og OK.",
            "usb_storage": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.\n2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\n3. Dobbeltklik på DWORD-værdien 'Start'.\n4. Sæt den til 4 for at deaktivere USB-lagring. (Sæt til 3 for at aktivere igen).",
            "windows_update": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.\n2. Find 'Windows Update' i bunden af listen.\n3. Dobbeltklik, skift Starttype til 'Automatisk' eller 'Automatisk (forsinket start)'.\n4. Klik Anvend og start tjenesten.",
            
            # Defender
            "pua_protection": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.\n2. Skriv kommandoen: Set-MpPreference -PUAProtection Enabled\n3. Tryk Enter. Luk vinduet.",
            "defender_rtp": "1. Åbn 'Windows Sikkerhed' fra proceslinjen eller Start-menuen.\n2. Gå til 'Virus- og trusselsbeskyttelse'.\n3. Klik på 'Administrer indstillinger'.\n4. Slå 'Realtidsbeskyttelse' TIL.",
            "defender_tamper": "1. Åbn 'Windows Sikkerhed' og gå til 'Virus- og trusselsbeskyttelse'.\n2. Klik på 'Administrer indstillinger'.\n3. Rul ned og slå 'Beskyttelse mod ændringer' (Tamper Protection) TIL.",
            "defender_cloud": "1. Åbn 'Windows Sikkerhed' og gå til 'Virus- og trusselsbeskyttelse'.\n2. Klik på 'Administrer indstillinger'.\n3. Slå 'Skybaseret beskyttelse' TIL.",
            "defender_archive": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.\n2. Skriv kommandoen: Set-MpPreference -DisableArchiveScanning 0\n3. Tryk Enter for at tillade scanning af zip/arkiv-filer.",
            "defender_network": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.\n2. Skriv kommandoen: Set-MpPreference -EnableNetworkProtection Enabled\n3. Tryk Enter for at slå netværksbeskyttelse til mod ondsindede IP'er.",
            "controlled_folder": "1. Åbn 'Windows Sikkerhed'.\n2. Gå til 'Virus- og trusselsbeskyttelse'.\n3. Rul ned og klik på 'Administrer beskyttelse mod ransomware'.\n4. Slå 'Styret mappeadgang' (Controlled folder access) TIL."
        }

        self.setup_ui()
        self.apply_stylesheet()

    def get_detailed_guide(self, check_id, raw_guide):
        """
        Slår op i databasen baseret på check_id. Hvis ID'et findes, returneres den fulde trin-for-trin guide.
        Hvis guiden allerede indeholder formatering (fra JSON filen), renses den for at sikre ensartethed.
        """
        if check_id in self.known_guides:
            return self.known_guides[check_id]
            
        # Fallback hvis check_id ikke findes (f.eks. for fremtidige opdateringer af JSON)
        raw_clean = str(raw_guide).replace("<br>", "\n").strip()
        
        if raw_clean.startswith("1. "):
            return raw_clean
            
        return f"1. Gennemgå følgende systemanvisning for afhjælpning:\n   {raw_clean}\n2. Udfør konfigurationen med administratorrettigheder.\n3. Bekræft ændringen og genstart systemet hvis nødvendigt."

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)

        # Header layout
        header_layout = QHBoxLayout()
        title_label = QLabel("Enterprise Sårbarheds- & Afhjælpningsrapport")
        title_label.setObjectName("header")
        
        self.score_label = QLabel("Score: N/A")
        self.score_label.setObjectName("score_label")
        self.score_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        
        header_layout.addWidget(title_label)
        header_layout.addWidget(self.score_label)
        main_layout.addLayout(header_layout)

        # Rapport visning
        self.report_display = QTextBrowser()
        self.report_display.setOpenExternalLinks(False)
        self.report_display.setHtml(
            "<div style='text-align:center; color:#a6adc8; margin-top:200px;'>"
            "<h2>Ingen rapport indlæst</h2>"
            "<p>Klik på 'Åbn JSON Rapport' for at indlæse en scanningsfil og generere handlingsplanen.</p>"
            "</div>"
        )
        main_layout.addWidget(self.report_display)

        # Knapper
        btn_layout = QHBoxLayout()
        self.load_btn = QPushButton("Åbn JSON Rapport")
        self.load_btn.setCursor(Qt.PointingHandCursor)
        self.load_btn.clicked.connect(self.load_json)
        
        self.export_btn = QPushButton("Eksporter Handlingsplan (TXT)")
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_text_report)
        self.export_btn.setEnabled(False)

        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.export_btn)
        main_layout.addLayout(btn_layout)

    def load_json(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Vælg JSON Sikkerhedsrapport", 
            "", 
            "JSON Filer (*.json);;Alle filer (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.report_data = json.load(f)
                
                if "metadata" not in self.report_data:
                    raise ValueError("Ugyldigt filformat: Mangler metadata.")
                
                self.render_html_view()
                self.export_btn.setEnabled(True)
                
            except Exception as e:
                QMessageBox.critical(self, "Fejl ved indlæsning", f"Kunne ikke indlæse filen:\n{str(e)}")

    def render_html_view(self):
        if not self.report_data: return

        meta = self.report_data.get("metadata", {})
        score = meta.get("score", 0)
        scan_time = meta.get("scan_time", "Ukendt")
        
        score_color = "#a6e3a1" if score >= 85 else ("#f9e2af" if score >= 65 else "#f38ba8")
        self.score_label.setText(f"<span style='color:{score_color}; font-size:24px;'>Score: {score}/100</span>")

        cat_names = {
            "hardware": "Hardware & Kernesikkerhed",
            "identity": "Identitet & Adgangskontrol",
            "network": "Netværk & Protokoller",
            "defender": "Defender & Trusselsbeskyttelse",
            "forensics": "PowerShell & Forensics",
            "os": "OS Konfiguration & Tjenester"
        }

        html = f"""
        <style>
            h2 {{ color: #cba6f7; border-bottom: 1px solid #45475a; padding-bottom: 5px; font-size: 18px; margin-top: 20px; }}
            h3 {{ color: #f38ba8; margin-bottom: 2px; font-size: 15px; }}
            .issue-box {{ background-color: #181825; border-left: 4px solid #f38ba8; padding: 12px; margin-bottom: 15px; border-radius: 4px; }}
            .critical-badge {{ background-color: #f38ba8; color: #11111b; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 10px; }}
            .info-text {{ color: #bac2de; font-size: 13px; margin-bottom: 8px; }}
            .remediation-box {{ background-color: #11111b; border: 1px solid #313244; padding: 10px; border-radius: 4px; color: #a6e3a1; font-size: 13px; line-height: 1.5; }}
        </style>
        <div style="font-family: 'Segoe UI', Arial, sans-serif;">
            <p style="color:#bac2de; font-size:14px;">Viser udelukkende identificerede sårbarheder og fejl fra scanningen udført: <b>{scan_time}</b></p>
        """

        issues_found = 0

        for cat_key, cat_data in self.report_data.items():
            if cat_key == "metadata": continue
            
            failed_checks = {k: v for k, v in cat_data.items() if not v.get("secure", True)}
            
            if failed_checks:
                cat_title = cat_names.get(cat_key, cat_key.capitalize())
                html += f"<h2>{cat_title}</h2>"
                
                for check_id, details in failed_checks.items():
                    issues_found += 1
                    name = details.get("name", check_id)
                    val = str(details.get("value", "Ukendt")).replace("<", "").replace(">", "")
                    critical = details.get("critical", False)
                    crit_badge = "<span class='critical-badge'>KRITISK SÅRBARHED</span>" if critical else ""
                    
                    # Generer den komplette detaljerede vejledning dynamisk baseret på check_id
                    raw_guide = details.get("remediation_guide", "")
                    detailed_guide = self.get_detailed_guide(check_id, raw_guide).replace('\n', '<br>')
                    
                    html += f"""
                    <div class='issue-box'>
                        <h3>[FEJL] {name} {crit_badge}</h3>
                        <div class='info-text'><b>Aflæst værdi/status:</b> {val}</div>
                        <div class='remediation-box'>
                            <b>LØSNINGSVEJLEDNING - TRIN FOR TRIN:</b><br>{detailed_guide}
                        </div>
                    </div>
                    """

        if issues_found == 0:
            html += """
            <div style="text-align:center; padding: 50px;">
                <h2 style="color:#a6e3a1; border:none;">🎉 Ingen sårbarheder fundet!</h2>
                <p style="color:#bac2de;">Systemet overholder alle 50+ sikkerhedskrav.</p>
            </div>
            """

        html += "</div>"
        self.report_display.setHtml(html)

    def export_text_report(self):
        if not self.report_data: return

        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Gem Handlingsplan som Tekstfil", 
            f"Handlingsplan_{datetime.now().strftime('%Y%m%d_%H%M')}.txt", 
            "Tekstfiler (*.txt);;Markdown Filer (*.md)"
        )
        
        if not file_path: return

        meta = self.report_data.get("metadata", {})
        score = meta.get("score", 0)
        scan_time = meta.get("scan_time", "Ukendt")
        
        cat_names = {
            "hardware": "Hardware & Kernesikkerhed",
            "identity": "Identitet & Adgangskontrol",
            "network": "Netværk & Protokoller",
            "defender": "Defender & Trusselsbeskyttelse",
            "forensics": "PowerShell & Forensics",
            "os": "OS Konfiguration & Tjenester"
        }

        lines = []
        lines.append("=" * 80)
        lines.append("          ENTERPRISE SIKKERHEDS- OG AFHJÆLPNINGSRAPPORT (HANDLINGSPLAN)")
        lines.append("=" * 80)
        lines.append(f"Dato for scanning:     {scan_time}")
        lines.append(f"Samlet Sikkerhedsscore: {score} / 100")
        lines.append("Beskrivelse:            Dette dokument indeholder udelukkende punkter, der")
        lines.append("                        kræver administrativ handling for at lukke sårbarheder.")
        lines.append("-" * 80)
        lines.append("")

        issues_found = 0

        for cat_key, cat_data in self.report_data.items():
            if cat_key == "metadata": continue
            
            failed_checks = {k: v for k, v in cat_data.items() if not v.get("secure", True)}
            
            if failed_checks:
                cat_title = cat_names.get(cat_key, cat_key.upper())
                lines.append(f"KATEGORI: {cat_title}")
                lines.append("-" * 80)
                
                for check_id, details in failed_checks.items():
                    issues_found += 1
                    name = details.get("name", check_id)
                    val = str(details.get("value", "Ukendt"))
                    critical = "JA (Høj Prioritet)" if details.get("critical", False) else "NEJ"
                    
                    # Generer vejledningen via opslag på check_id
                    raw_guide = details.get("remediation_guide", "Ingen vejledning.")
                    detailed_guide_lines = self.get_detailed_guide(check_id, raw_guide).split('\n')
                    guide_clean = "Trin for trin:\n      " + "\n      ".join(detailed_guide_lines)
                    
                    lines.append(f"[FEJL] {name}")
                    lines.append(f"  - Kritisk Sårbarhed: {critical}")
                    lines.append(f"  - Aktuel Værdi/Status: {val}")
                    lines.append(f"  - LØSNING:")
                    lines.append(f"      {guide_clean}")
                    lines.append("")
                
                lines.append("=" * 80)
                lines.append("")

        if issues_found == 0:
            lines.append("INGEN SÅRBARHEDER FUNDET. SYSTEMET ER FULDT HÆRDET.")
        
        lines.append("BEMÆRK: Da flere af ændringerne involverer LSA (Local Security Authority) og ")
        lines.append("registreringsdatabasen, anbefales det på det kraftigste at genstarte computeren,")
        lines.append("når alle trin er udført, for at sikre at ændringerne træder i kraft.")
        lines.append("")
        lines.append("Rapport genereret af CyberSec Pro Enterprise Auditor.")

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines))
            QMessageBox.information(self, "Succes", f"Handlingsplanen blev gemt succesfuldt i:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Fejl", f"Der opstod en fejl under lagring af filen:\n{str(e)}")

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #11111b; }
            QWidget { color: #cdd6f4; font-family: 'Segoe UI', Arial; }
            QLabel#header { font-size: 22px; font-weight: bold; color: #cba6f7; }
            QLabel#score_label { font-weight: bold; }
            QTextBrowser { background-color: #1e1e2e; border: 1px solid #313244; border-radius: 8px; padding: 15px; }
            QPushButton { background-color: #cba6f7; color: #11111b; border: none; border-radius: 6px; padding: 12px; font-weight: bold; font-size: 14px; }
            QPushButton:hover { background-color: #b4befe; }
            QPushButton:disabled { background-color: #313244; color: #6c7086; }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = SecurityReportAnalyzer()
    window.show()
    sys.exit(app.exec())