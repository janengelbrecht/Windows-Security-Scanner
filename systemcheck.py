import sys
import platform
import socket
import subprocess
import ctypes
import json
import winreg
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QPushButton, QLabel, QTextBrowser, QHBoxLayout, QProgressBar,
    QDialog, QDialogButtonBox
)
from PySide6.QtCore import QThread, Signal, Qt, QUrl
from PySide6.QtGui import QFont

# --- 1. DATAMODEL & KONFIGURATION ---

CATEGORIES = {
    "hardware": "1. Hardware & Kernesikkerhed",
    "identity": "2. Identitet & Adgangskontrol",
    "network": "3. Netværk & Protokoller",
    "defender": "4. Defender & Trusselsbeskyttelse",
    "forensics": "5. PowerShell & Forensics",
    "os": "6. OS Konfiguration & Tjenester"
}

# (id, category, name, hive, path, key, expected_val, critical, deduction, secure_if_missing)
REGISTRY_CHECKS = [
    # Identity & LSA
    ("lsa_protection", "identity", "LSA Protection (RunAsPPL)", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1, True, 7, False),
    ("wdigest", "identity", "WDigest Caching (Anti-Mimikatz)", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0, True, 7, True),
    ("lm_hash", "identity", "LM Hash Lagring Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash", 1, True, 5, True),
    ("cached_logons", "identity", "Cached Logons Begrænset (Max 2)", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", 2, False, 2, False),
    ("blank_passwords", "identity", "Blanke Passwords Begrænset", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse", 1, True, 5, True),
    ("legal_notice", "identity", "Login Banner Opsat", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "legalnoticecaption", "", False, 1, False),
    
    # Network
    ("smb_signing", "network", "SMB Signing Enforced", winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1, True, 6, False),
    ("ntlmv2_only", "network", "Kun NTLMv2 Tilladt", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 5, True, 8, False),
    ("llmnr", "network", "LLMNR Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0, False, 3, False),
    ("rdp_nla", "network", "RDP Network Level Auth", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1, True, 5, True),
    ("ipv6_disabled", "network", "IPv6 Deaktiveret (hvis ubrugt)", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", 255, False, 1, False),
    ("remote_registry", "network", "Remote Registry Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start", 4, False, 3, False),
    ("wpad", "network", "WPAD Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad", "WpadOverride", 1, False, 2, False),
    ("icmp_redirects", "network", "ICMP Redirects Ignoreret", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableICMPRedirect", 0, False, 2, True),
    
    # Forensics
    ("ps_script_logging", "forensics", "PS Script Block Logging", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1, True, 6, False),
    ("ps_transcription", "forensics", "PS Transcription", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", 1, False, 4, False),
    ("ps_module_logging", "forensics", "PS Module Logging", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", 1, False, 3, False),
    ("cmd_auditing", "forensics", "CMD Command Line Auditing", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled", 1, False, 4, False),
    
    # OS & Services
    ("uac", "os", "UAC Aktiveret", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1, True, 7, False),
    ("autorun", "os", "Autorun Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255, False, 3, False),
    ("fast_startup", "os", "Fast Startup Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", 0, False, 2, False),
    ("clear_pagefile", "os", "Ryd Pagefile ved Nedlukning", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown", 1, False, 2, False),
    ("sticky_keys", "os", "Sticky Keys Genvej Deaktiveret", winreg.HKEY_CURRENT_USER, r"Control Panel\Accessibility\StickyKeys", "Flags", "506", False, 1, False),
    ("smartscreen", "os", "SmartScreen for Explorer", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1, False, 3, False),
    ("telemetry", "os", "Telemetri Begrænset", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0, False, 1, False),
    ("crash_dump", "os", "Kernekræsh-dumps Begrænset", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", 0, False, 1, False),
    ("usb_storage", "os", "USB Masselagring Deaktiveret", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start", 4, False, 2, False),
    
    # Defender & PUA
    ("pua_protection", "defender", "PUA (Potentially Unwanted App) Blokering", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine", "MpEnablePus", 1, False, 3, False),
]

# Detaljerede afhjælpningsvejledninger med HTML formatering
REMEDIATIONS = {
    # Hardware
    "tpm": "1. Genstart computeren og tryk på tasten for at åbne BIOS/UEFI (ofte F2, Del eller F12).<br>2. Naviger til sikkerhedsindstillingerne (Security/Advanced).<br>3. Aktiver TPM (kan hedde fTPM på AMD eller PTT på Intel systemer).<br>4. Gem ændringerne og genstart.",
    "secure_boot": "1. Genstart computeren og gå ind i BIOS/UEFI.<br>2. Find menuen 'Boot' eller 'Security'.<br>3. Sæt 'Secure Boot' til 'Enabled'.<br>4. Gem ændringerne og afslut.",
    "bitlocker": "1. Tryk på Start, søg efter 'Kontrolpanel' og åbn det.<br>2. Gå til 'System og sikkerhed' -> 'BitLocker-drevkryptering'.<br>3. Klik på 'Slå BitLocker til' ud for systemdrevet.<br>4. Følg guiden for at gemme din genoprettelsesnøgle og starte krypteringen.",
    "vbs": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.<br>2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> System -> Device Guard.<br>3. Dobbeltklik på 'Slå virtualiseringsbaseret sikkerhed til'.<br>4. Vælg 'Aktiveret' og klik OK. Genstart computeren.",
    "memory_integrity": "1. Tryk på Start og åbn 'Windows Sikkerhed'.<br>2. Klik på 'Enhedssikkerhed'.<br>3. Vælg 'Nulstillingsisolation' (Core isolation) detaljer.<br>4. Slå 'Hukommelsesintegritet' TIL og genstart computeren.",
    "credential_guard": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.<br>2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> System -> Device Guard.<br>3. Dobbeltklik på 'Slå virtualiseringsbaseret sikkerhed til'.<br>4. Vælg 'Aktiveret' og under indstillinger for Credential Guard, vælg 'Enabled med UEFI lock'. Klik OK.",
    "dma_protection": "1. Genstart computeren og gå ind i BIOS/UEFI.<br>2. Find indstillinger for virtualisering (VT-d for Intel, AMD-Vi for AMD).<br>3. Aktiver Kernel DMA Protection eller IOMMU.<br>4. Gem og afslut.",
    
    # Identity
    "lsa_protection": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa<br>3. Højreklik, vælg Ny -> DWORD-værdi (32-bit) og kald den 'RunAsPPL'.<br>4. Sæt Værdidata til 1, klik OK og genstart computeren.",
    "wdigest": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest<br>3. Højreklik, opret eller ret DWORD-værdien 'UseLogonCredential'.<br>4. Sæt Værdidata til 0 og klik OK.",
    "guest_disabled": "1. Højreklik på Start og vælg 'Computeradministration' (compmgmt.msc).<br>2. Gå til 'Lokale brugere og grupper' -> 'Brugere'.<br>3. Højreklik på kontoen 'Gæst' (Guest) og vælg Egenskaber.<br>4. Sæt flueben i 'Kontoen er deaktiveret' og klik OK.",
    "lm_hash": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.<br>3. Dobbeltklik på 'Netværkssikkerhed: Gem ikke LAN Manager-hashværdi af næste adgangskodeændring'.<br>4. Vælg 'Aktiveret' og klik OK.",
    "cached_logons": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.<br>3. Dobbeltklik på 'Interaktivt logon: Antal tidligere logons til cache...'.<br>4. Sæt værdien til 2 (eller lavere) og klik OK.",
    "blank_passwords": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.<br>3. Dobbeltklik på 'Konti: Begræns brugen af tomme adgangskoder til konsollogon'.<br>4. Vælg 'Aktiveret' og klik OK.",
    "legal_notice": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.<br>3. Udfyld en standardtekst i 'Interaktivt logon: Meddelelsestekst til brugere...'.<br>4. Udfyld titlen i 'Interaktivt logon: Meddelelsestitel til brugere...'. Klik OK.",
    "admin_disabled": "1. Højreklik på Start og vælg 'Computeradministration' (compmgmt.msc).<br>2. Gå til 'Lokale brugere og grupper' -> 'Brugere'.<br>3. Højreklik på kontoen 'Administrator' og vælg Egenskaber.<br>4. Sæt flueben i 'Kontoen er deaktiveret' og klik OK.",
    "laps_enabled": "1. Download og installer Microsoft LAPS (Local Administrator Password Solution).<br>2. Konfigurer Group Policy Object (GPO) til at aktivere LAPS for klienten.<br>3. Tildel rettigheder i Active Directory til at læse adgangskoderne.",
    "admin_count_safe": "1. Højreklik på Start og vælg 'Computeradministration' (compmgmt.msc).<br>2. Gå til 'Lokale brugere og grupper' -> 'Grupper'.<br>3. Dobbeltklik på 'Administratorer'.<br>4. Fjern brugere/grupper der ikke strengt behøver administratorrettigheder, så der er maks 3 tilbage.",
    
    # Network
    "smb1_disabled": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.<br>2. Kopiér og indsæt følgende kommando: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol<br>3. Tryk Enter. Genstart computeren, når du bliver bedt om det.",
    "smb_signing": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters<br>3. Find eller opret DWORD 'RequireSecuritySignature'.<br>4. Sæt værdien til 1 og klik OK.",
    "ntlmv2_only": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.<br>3. Find 'Netværkssikkerhed: Godkendelsesniveau for LAN Manager'.<br>4. Sæt den til 'Send kun NTLMv2-svar. Afvis LM og NTLM'. Klik OK.",
    "llmnr": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.<br>2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> Netværk -> DNS-klient.<br>3. Dobbeltklik på 'Deaktiver multicastnavnefortolkning'.<br>4. Vælg 'Aktiveret' og klik OK.",
    "netbios": "1. Tryk Windows-tast + R, skriv 'ncpa.cpl' og tryk Enter.<br>2. Højreklik på dit primære netværkskort og vælg Egenskaber.<br>3. Dobbeltklik på 'Internet Protocol Version 4 (TCP/IPv4)' og klik på knappen 'Avanceret'.<br>4. Under fanen WINS, vælg 'Deaktiver NetBIOS over TCP/IP'. Klik OK.",
    "rdp_nla": "1. Tryk Windows-tast + R, skriv 'sysdm.cpl' og tryk Enter.<br>2. Gå til fanen 'Fjernadgang' (Remote).<br>3. Under Fjernskrivebord, marker boksen 'Tillad kun forbindelser fra computere, der kører Fjernskrivebord med Godkendelse på netværksniveau'. Klik OK.",
    "ipv6_disabled": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters<br>3. Opret DWORD-værdien 'DisabledComponents'.<br>4. Sæt værdien til 255 (Decimal) og klik OK.",
    "remote_registry": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.<br>2. Find tjenesten 'Fjernregistreringsdatabase' (Remote Registry).<br>3. Dobbeltklik på den og sæt Starttype til 'Deaktiveret'.<br>4. Klik på 'Stop' hvis tjenesten kører, og derefter OK.",
    "wpad": "1. Tryk Windows-tast + I for at åbne Indstillinger.<br>2. Gå til Netværk og internet -> Proxy.<br>3. Slå funktionen 'Find automatisk indstillinger' FRA.",
    "icmp_redirects": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters<br>3. Find eller opret DWORD 'EnableICMPRedirect'.<br>4. Sæt værdien til 0 og klik OK.",
    "firewall_domain": "1. Tryk Windows-tast + R, skriv 'wf.msc' og tryk Enter.<br>2. Klik på 'Egenskaber for Windows Defender Firewall'.<br>3. Under fanen 'Domæneprofil', sæt Firewalltilstand til 'Til (anbefales)'. Klik OK.",
    "firewall_private": "1. Tryk Windows-tast + R, skriv 'wf.msc' og tryk Enter.<br>2. Klik på 'Egenskaber for Windows Defender Firewall'.<br>3. Under fanen 'Privat profil', sæt Firewalltilstand til 'Til (anbefales)'. Klik OK.",
    "firewall_public": "1. Tryk Windows-tast + R, skriv 'wf.msc' og tryk Enter.<br>2. Klik på 'Egenskaber for Windows Defender Firewall'.<br>3. Under fanen 'Offentlig profil', sæt Firewalltilstand til 'Til (anbefales)'. Klik OK.",
    "risky_ports": "1. Åbn PowerShell som Administrator.<br>2. Kør 'Get-NetTCPConnection -State Listen' for at finde porte som f.eks. 21, 23 eller 69.<br>3. Kør 'Get-Process -Id [PID]' (PID fra forrige trin) for at se programmet.<br>4. Afinstaller programmet eller deaktiver dets tjeneste i services.msc.",
    
    # Forensics
    "ps_script_logging": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.<br>2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> Windows-komponenter -> Windows PowerShell.<br>3. Dobbeltklik på 'Slå logføring af PowerShell-scriptblok til'.<br>4. Vælg 'Aktiveret' og klik OK.",
    "ps_transcription": "1. I gpedit.msc, naviger til Windows PowerShell-mappen.<br>2. Find og dobbeltklik på 'Slå PowerShell-transskription til'.<br>3. Vælg 'Aktiveret'.<br>4. Vælg eventuelt en output-mappe til logfilerne og klik OK.",
    "ps_module_logging": "1. I gpedit.msc, naviger til Windows PowerShell-mappen.<br>2. Find og dobbeltklik på 'Slå modullogføring til'.<br>3. Vælg 'Aktiveret'.<br>4. Klik på 'Vis' ud for Modulnavne, skriv '*' for at logge alle moduler, og klik OK.",
    "cmd_auditing": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.<br>2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> System -> Overvågning af procesoprettelse.<br>3. Dobbeltklik på politikken, vælg 'Aktiveret'.<br>4. Marker boksen, så kommandolinjen inkluderes. Klik OK.",
    "ps_v2_disabled": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.<br>2. Kopiér og indsæt: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2<br>3. Tryk Enter. Genstart systemet efterfølgende.",
    "ps_exec_policy": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.<br>2. Skriv kommandoen: Set-ExecutionPolicy RemoteSigned<br>3. Tryk Enter og bekræft ved at taste 'Y'.",
    "audit_logon": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Overvågningspolitik.<br>3. Dobbeltklik på 'Overvåg logonhændelser'.<br>4. Sæt flueben i både 'Succes' og 'Fejl'. Klik OK.",
    
    # OS & Services
    "uac": "1. Tryk på Start, skriv 'UAC' og tryk Enter for at åbne Kontrol af brugerkonti.<br>2. Træk skyderen helt i top ('Giv altid besked, når...').<br>3. Klik OK og bekræft handlingen.",
    "autorun": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer<br>3. Opret en ny DWORD-værdi (32-bit) og kald den 'NoDriveTypeAutoRun'.<br>4. Sæt Værdidata til 255 (Decimal) og klik OK.",
    "fast_startup": "1. Tryk Windows-tast + R, skriv 'powercfg.cpl' og tryk Enter.<br>2. Klik på 'Vælg, hvad tænd/sluk-knapperne gør' til venstre.<br>3. Klik på 'Rediger indstillinger, der aktuelt ikke er tilgængelige'.<br>4. Fjern fluebenet ved 'Aktivér hurtig start (anbefales)'. Klik OK.",
    "clear_pagefile": "1. Tryk Windows-tast + R, skriv 'secpol.msc' og tryk Enter.<br>2. Naviger til: Lokale politikker -> Sikkerhedsindstillinger.<br>3. Dobbeltklik på 'Nedlukning: Ryd sidefil til virtuel hukommelse'.<br>4. Vælg 'Aktiveret' og klik OK.",
    "sticky_keys": "1. Tryk på Shift-tasten 5 gange hurtigt efter hinanden for at udløse Træge Taster-boksen.<br>2. Klik på linket i pop-up vinduet for at åbne Indstillinger for tastaturet.<br>3. Slå genvejstasterne FRA for både 'Træge taster' (Sticky Keys) og 'Filtertaster'.",
    "smartscreen": "1. Tryk på Start og åbn 'Windows Sikkerhed'.<br>2. Klik på 'App- og browserstyring'.<br>3. Klik på 'Omdømmebaserede beskyttelsesindstillinger'.<br>4. Slå 'Kontrollér apps og filer' (SmartScreen for Windows) TIL.",
    "telemetry": "1. Tryk Windows-tast + R, skriv 'gpedit.msc' og tryk Enter.<br>2. Naviger til: Computerkonfiguration -> Administrative skabeloner -> Windows-komponenter -> Dataindsamling.<br>3. Dobbeltklik på 'Tillad telemetri' (eller Diagnosedata).<br>4. Vælg 'Aktiveret' og sæt niveauet til 'Sikkerhed' (0). Klik OK.",
    "crash_dump": "1. Tryk Windows-tast + R, skriv 'sysdm.cpl' og tryk Enter.<br>2. Gå til fanen 'Avanceret'.<br>3. Under 'Start og genoprettelse', klik på 'Indstillinger'.<br>4. Under 'Skriv fejlfindingsoplysninger', vælg '(Ingen)' fra dropdown-menuen. Klik OK.",
    "print_spooler": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.<br>2. Find tjenesten 'Print Spooler' (Printkø).<br>3. Dobbeltklik og skift Starttype til 'Deaktiveret'.<br>4. Klik på 'Stop' og derefter OK.",
    "xbox_services": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.<br>2. Find alle tjenester der starter med 'Xbox' (f.eks. Xbox Live Auth Manager).<br>3. Dobbeltklik på hver af dem og sæt Starttype til 'Deaktiveret'.<br>4. Klik 'Stop' og OK.",
    "usb_storage": "1. Tryk Windows-tast + R, skriv 'regedit' og tryk Enter.<br>2. Naviger til: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR<br>3. Dobbeltklik på DWORD-værdien 'Start'.<br>4. Sæt den til 4 for at deaktivere USB-lagring. (Sæt til 3 for at aktivere igen).",
    "windows_update": "1. Tryk Windows-tast + R, skriv 'services.msc' og tryk Enter.<br>2. Find 'Windows Update' i bunden af listen.<br>3. Dobbeltklik, skift Starttype til 'Automatisk' eller 'Automatisk (forsinket start)'.<br>4. Klik Anvend og start tjenesten.",
    
    # Defender
    "pua_protection": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.<br>2. Skriv kommandoen: Set-MpPreference -PUAProtection Enabled<br>3. Tryk Enter. Luk vinduet.",
    "defender_rtp": "1. Åbn 'Windows Sikkerhed' fra proceslinjen eller Start-menuen.<br>2. Gå til 'Virus- og trusselsbeskyttelse'.<br>3. Klik på 'Administrer indstillinger'.<br>4. Slå 'Realtidsbeskyttelse' TIL.",
    "defender_tamper": "1. Åbn 'Windows Sikkerhed' og gå til 'Virus- og trusselsbeskyttelse'.<br>2. Klik på 'Administrer indstillinger'.<br>3. Rul ned og slå 'Beskyttelse mod ændringer' (Tamper Protection) TIL.",
    "defender_cloud": "1. Åbn 'Windows Sikkerhed' og gå til 'Virus- og trusselsbeskyttelse'.<br>2. Klik på 'Administrer indstillinger'.<br>3. Slå 'Skybaseret beskyttelse' TIL.",
    "defender_archive": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.<br>2. Skriv kommandoen: Set-MpPreference -DisableArchiveScanning 0<br>3. Tryk Enter for at tillade scanning af zip/arkiv-filer.",
    "defender_network": "1. Højreklik på Start og vælg 'Windows PowerShell (Admin)'.<br>2. Skriv kommandoen: Set-MpPreference -EnableNetworkProtection Enabled<br>3. Tryk Enter for at slå netværksbeskyttelse til mod ondsindede IP'er.",
    "controlled_folder": "1. Åbn 'Windows Sikkerhed'.<br>2. Gå til 'Virus- og trusselsbeskyttelse'.<br>3. Rul ned og klik på 'Administrer beskyttelse mod ransomware'.<br>4. Slå 'Styret mappeadgang' (Controlled folder access) TIL."
}


# --- 2. BACKEND SCANNER THREAD ---

class EnterpriseScannerWorker(QThread):
    progress_update = Signal(str, int)
    scan_complete = Signal(dict)
    error_occurred = Signal(str)

    def run(self):
        try:
            report = {
                "metadata": {
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "is_admin": self._is_admin(),
                    "total_checks": 0,
                    "score": 100
                }
            }
            for cat_key in CATEGORIES.keys():
                report[cat_key] = {}

            if not report["metadata"]["is_admin"]:
                self.error_occurred.emit("Kritisk fejl: Enterprise-scanning KRÆVER administratorrettigheder for at læse WMI og sikre registre.")
                return

            self.progress_update.emit("Analyserer 30+ Registreringsnøgler...", 15)
            self._audit_registry(report)
            
            self.progress_update.emit("Kører WMI, Netværk & Hardware Analyse (PowerShell)...", 45)
            self._audit_powershell(report)
            
            self.progress_update.emit("Sammenstiller Score & Eksporterer Data...", 90)
            self._finalize_report(report)

            self.progress_update.emit("Færdig.", 100)
            self.scan_complete.emit(report)

        except Exception as e:
            self.error_occurred.emit(str(e))

    def _is_admin(self) -> bool:
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return False

    def _audit_registry(self, r):
        for check_id, category, name, hive, path, key, expected, critical, deduction, secure_if_missing in REGISTRY_CHECKS:
            secure = False
            val = "Ikke Konfigureret"
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as reg_key:
                    val, _ = winreg.QueryValueEx(reg_key, key)
                    secure = (val == expected)
            except FileNotFoundError:
                if secure_if_missing:
                    secure = True
                    val = "Standard (Sikker)"
            except Exception:
                val = "Læsefejl"

            r[category][check_id] = {
                "name": name,
                "secure": secure,
                "value": str(val),
                "critical": critical,
                "deduction": deduction
            }

    def _audit_powershell(self, r):
        ps_script = """
        $Out = @{}
        
        # 1. Hardware
        try { $Out.tpm = (Get-Tpm).TpmPresent } catch { $Out.tpm = $false }
        try { $Out.secure_boot = Confirm-SecureBootUEFI } catch { $Out.secure_boot = $false }
        try { 
            $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            $Out.vbs = $DG.VirtualizationBasedSecurityStatus -gt 0
            $Out.memory_integrity = $DG.SecurityServicesRunning -contains 2
            $Out.credential_guard = $DG.SecurityServicesRunning -contains 1
        } catch { $Out.vbs = $false; $Out.memory_integrity = $false; $Out.credential_guard = $false }
        try { $Out.bitlocker = ((Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus -eq 'FullyEncrypted') } catch { $Out.bitlocker = $false }
        try { $Out.dma_protection = (Get-ItemProperty HKLM:\System\CurrentControlSet\Control\DmaSecurity\Default).KernelDmaProtectionEnabled -eq 1 } catch { $Out.dma_protection = $false }

        # 2. Identity
        try { $Out.guest_disabled = -not (Get-LocalUser -Name Guest).Enabled } catch { $Out.guest_disabled = $false }
        try { $Out.admin_disabled = -not (Get-LocalUser -Name Administrator).Enabled } catch { $Out.admin_disabled = $false }
        try { $Out.laps_enabled = (Get-Command Get-LapsDiagnostics -ErrorAction SilentlyContinue) -ne $null } catch { $Out.laps_enabled = $false }
        try { $Out.admin_count_safe = (@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)).Count -le 3 } catch { $Out.admin_count_safe = $false }

        # 3. Network
        try { $Out.smb1_disabled = -not (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { $Out.smb1_disabled = $false }
        try { $Out.netbios = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -and $_.TcpipNetbiosOptions -ne 2 }).Count -eq 0 } catch { $Out.netbios = $false }
        try { $Out.fw_domain = (Get-NetFirewallProfile -Name Domain).Enabled -eq 1 } catch { $Out.fw_domain = $false }
        try { $Out.fw_private = (Get-NetFirewallProfile -Name Private).Enabled -eq 1 } catch { $Out.fw_private = $false }
        try { $Out.fw_public = (Get-NetFirewallProfile -Name Public).Enabled -eq 1 } catch { $Out.fw_public = $false }
        try { $Out.risky_ports = (@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in @(21, 23, 69) })).Count -eq 0 } catch { $Out.risky_ports = $true }

        # 4. Forensics
        try { $Out.ps_v2_disabled = -not (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq 'Enabled' } catch { $Out.ps_v2_disabled = $true }
        try { $Out.ps_exec_policy = (Get-ExecutionPolicy) -in @('Restricted', 'RemoteSigned', 'AllSigned') } catch { $Out.ps_exec_policy = $false }
        
        # 5. OS Services
        try { $Out.print_spooler = (Get-Service -Name Spooler).Status -ne 'Running' } catch { $Out.print_spooler = $false }
        try { $Out.xbox_services = (Get-Service -Name XblAuthManager -ErrorAction SilentlyContinue).Status -ne 'Running' } catch { $Out.xbox_services = $false }
        try { $Out.windows_update = (Get-Service wuauserv -ErrorAction SilentlyContinue).StartType -in @('Automatic', 'AutomaticDelayedStart') } catch { $Out.windows_update = $false }
        
        # 6. Defender
        try { 
            $Def = Get-MpPreference
            $Out.defender_rtp = -not $Def.DisableRealtimeMonitoring
            $Out.defender_tamper = (Get-MpComputerStatus).IsTamperProtected
            $Out.defender_cloud = $Def.MAPSReporting -gt 0
            $Out.defender_archive = -not $Def.DisableArchiveScanning
            $Out.defender_network = $Def.EnableNetworkProtection -eq 1
            $Out.controlled_folder = $Def.EnableControlledFolderAccess -eq 1
        } catch {}

        $Out | ConvertTo-Json -Compress
        """
        try:
            res = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script], stdout=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            data = json.loads(res.stdout.strip())
            
            ps_map = [
                ("hardware", "tpm", "TPM 2.0 Modul", True, 3),
                ("hardware", "secure_boot", "Secure Boot", True, 3),
                ("hardware", "vbs", "Virtualization-Based Security (VBS)", False, 2),
                ("hardware", "memory_integrity", "HVCI (Memory Integrity)", True, 6),
                ("hardware", "bitlocker", "BitLocker Systemdrev", True, 8),
                ("hardware", "dma_protection", "Kernel DMA Protection", False, 1),
                
                ("identity", "credential_guard", "Credential Guard", True, 6),
                ("identity", "guest_disabled", "Gæstekonto Deaktiveret", False, 3),
                ("identity", "admin_disabled", "Indbygget Admin Deaktiveret", False, 2),
                ("identity", "laps_enabled", "LAPS (Local Admin Password Solution)", False, 1),
                ("identity", "admin_count_safe", "Få Lokale Administratorer (Maks 3)", False, 3),
                
                ("network", "smb1_disabled", "SMBv1 Deaktiveret", True, 10),
                ("network", "netbios", "NetBIOS Deaktiveret", False, 3),
                ("network", "fw_domain", "Firewall: Domain Profile", True, 3),
                ("network", "fw_private", "Firewall: Private Profile", True, 3),
                ("network", "fw_public", "Firewall: Public Profile", True, 4),
                ("network", "risky_ports", "Ingen Åbne Usikre Porte (FTP/Telnet)", True, 5),
                
                ("forensics", "ps_v2_disabled", "PowerShell v2 Deaktiveret", False, 2),
                ("forensics", "ps_exec_policy", "Sikker PS Execution Policy", False, 3),
                
                ("os", "print_spooler", "Print Spooler Deaktiveret", False, 1),
                ("os", "xbox_services", "Xbox Tjenester Deaktiveret", False, 1),
                ("os", "windows_update", "Windows Update Tjeneste Auto", True, 5),
                
                ("defender", "defender_rtp", "Defender Real-Time Protection", True, 10),
                ("defender", "defender_tamper", "Defender Tamper Protection", True, 8),
                ("defender", "defender_cloud", "Defender Cloud Protection", False, 2),
                ("defender", "defender_archive", "Defender Archive Scanning", False, 1),
                ("defender", "defender_network", "Defender Network Protection", False, 2),
                ("defender", "controlled_folder", "Ransomware Beskyttelse (CFA)", False, 4),
            ]

            for cat, check_id, name, crit, deduc in ps_map:
                is_sec = data.get(check_id, False)
                r[cat][check_id] = {
                    "name": name,
                    "secure": is_sec,
                    "value": str(is_sec),
                    "critical": crit,
                    "deduction": deduc
                }
        except:
            pass

    def _finalize_report(self, r):
        score = 100
        count = 0
        for cat in CATEGORIES.keys():
            for check_id, check_data in r[cat].items():
                count += 1
                check_data["remediation_guide"] = REMEDIATIONS.get(check_id, "Ingen detaljeret vejledning tilgængelig for denne specifikke politik.")
                if not check_data["secure"]:
                    score -= check_data.get("deduction", 1)
        
        r["metadata"]["total_checks"] = count
        r["metadata"]["score"] = max(0, score)


# --- 3. BRUGERGRÆNSEFLADE (UI) ---

class RemediationDialog(QDialog):
    def __init__(self, check_name, title_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sikkerhedsanvisning")
        self.setFixedSize(550, 250)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI'; }
            QTextBrowser { background-color: #11111b; border: 1px solid #313244; border-radius: 6px; padding: 12px; font-size: 14px; }
            QPushButton { background-color: #89b4fa; color: #11111b; border-radius: 4px; padding: 8px 20px; font-weight: bold; }
            QPushButton:hover { background-color: #b4befe; }
        """)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"<h3 style='color:#f38ba8; margin:0;'>Fejl: {title_text}</h3>"))

        browser = QTextBrowser()
        remediation_text = REMEDIATIONS.get(check_name, "Ingen specifik løsningsvejledning fundet i databasen.")
        browser.setHtml(f"<div style='line-height:1.5;'>{remediation_text}</div>")
        layout.addWidget(browser)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok)
        btn_box.accepted.connect(self.accept)
        layout.addWidget(btn_box)


class EnterpriseSecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSec Pro - Udvidet Endpoint Audit")
        self.resize(1000, 900)
        self.title_map = {}
        self.setup_ui()
        self.apply_stylesheet()
        self.latest_report = None

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(25, 25, 25, 25)

        header_layout = QHBoxLayout()
        title_label = QLabel("Ultimate Endpoint Security Audit")
        title_label.setObjectName("header")
        self.score_label = QLabel("Score: N/A")
        self.score_label.setObjectName("score_label")
        self.score_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        
        header_layout.addWidget(title_label)
        header_layout.addWidget(self.score_label)
        main_layout.addLayout(header_layout)

        self.report_display = QTextBrowser()
        self.report_display.setOpenLinks(False) 
        self.report_display.anchorClicked.connect(self.handle_link_click)
        self.report_display.setHtml(
            "<div style='text-align:center; color:#a6adc8; margin-top:150px;'>"
            "<h2>50+ Point Zero Trust Analyse</h2>"
            "<p>Klar til at analysere Hardware, Adgangskontrol, Forensics, Defender og OS-politikker.</p>"
            "<p>Klik på røde og gule fejl i rapporten for detaljerede trin-for-trin afhjælpningsvejledninger.</p>"
            "<p><i>Kræver kørsel som Administrator.</i></p></div>"
        )
        main_layout.addWidget(self.report_display)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)

        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Dybdegående Analyse")
        self.scan_btn.clicked.connect(self.start_scan)
        self.export_btn = QPushButton("Eksporter Sikkerheds-JSON")
        self.export_btn.clicked.connect(self.export_json)
        self.export_btn.setEnabled(False)

        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.export_btn)
        main_layout.addLayout(btn_layout)

    def start_scan(self):
        self.scan_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.score_label.setText("Score: Analyserer...")
        self.report_display.setHtml("")
        
        self.worker = EnterpriseScannerWorker()
        self.worker.progress_update.connect(self.update_progress)
        self.worker.scan_complete.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def update_progress(self, text, val):
        self.status_label.setText(text)
        self.progress_bar.setValue(val)

    def on_scan_complete(self, report):
        self.latest_report = report
        total = report["metadata"]["total_checks"]
        self.status_label.setText(f"Analyse fuldført ({total} parametre tjekket). Klik på [LØS FEJL] for trin-for-trin vejledning.")
        self.progress_bar.hide()
        self.scan_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        score = report["metadata"]["score"]
        score_color = "#a6e3a1" if score >= 85 else ("#f9e2af" if score >= 65 else "#f38ba8")
        self.score_label.setText(f"<span style='color:{score_color}; font-size:24px;'>Score: {score}/100</span>")
        
        self.render_html_report(report)

    def on_scan_error(self, error_msg):
        self.status_label.setText("")
        self.progress_bar.hide()
        self.scan_btn.setEnabled(True)
        self.report_display.setHtml(f"<div style='color:#f38ba8; text-align:center; margin-top:50px;'><h2>Fejl</h2><p>{error_msg}</p></div>")

    def _render_row(self, check_id, check_data):
        name = check_data["name"]
        self.title_map[check_id] = name 
        is_secure = check_data["secure"]
        critical = check_data["critical"]
        
        color = "#a6e3a1" if is_secure else ("#f38ba8" if critical else "#f9e2af")
        
        if is_secure:
            status = f"<span style='color:{color};'>[PASS]</span>"
        else:
            status = f"<a href='remediate:{check_id}' style='color:{color}; text-decoration:none;'><b>[LØS FEJL]</b></a>"
            
        val = str(check_data.get("value", "")).replace("<", "").replace(">", "")
        if val in ["True", "1"]: val = "Aktiveret"
        if val in ["False", "0"]: val = "Deaktiveret"
            
        return f"<tr><th width='60%'>{name}:</th><td style='color:{color}; text-align:right;'>{status} &nbsp; {val}</td></tr>"

    def render_html_report(self, r):
        html = """
        <style>
            th { text-align: left; padding: 4px 0; color: #bac2de; font-weight: normal; font-size: 13px; border-bottom: 1px solid #313244; }
            td { padding: 4px 0; font-weight: bold; font-size: 13px; border-bottom: 1px solid #313244; }
            h2 { color: #89b4fa; margin-top: 5px; margin-bottom: 8px; font-size: 15px; text-transform: uppercase; letter-spacing: 1px; }
            .section { background-color: #181825; padding: 12px; border-radius: 8px; margin-bottom: 12px; border: 1px solid #313244; }
            a:hover { text-decoration: underline !important; }
        </style>
        <div style="font-family: 'Segoe UI', Arial, sans-serif;">
        """
        
        for cat_key, cat_title in CATEGORIES.items():
            if not r[cat_key]: continue
            html += f"<div class='section'><h2>{cat_title}</h2><table width='100%' cellspacing='0'>"
            for check_id, check_data in r[cat_key].items():
                html += self._render_row(check_id, check_data)
            html += "</table></div>"
            
        html += "</div>"
        self.report_display.setHtml(html)

    def handle_link_click(self, url: QUrl):
        link = url.toString()
        if link.startswith("remediate:"):
            check_key = link.split(":")[1]
            title = self.title_map.get(check_key, check_key)
            dialog = RemediationDialog(check_key, title, self)
            dialog.exec()

    def export_json(self):
        if not self.latest_report: return
        try:
            filename = f"Full_Audit_Udvidet_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.latest_report, f, indent=4, ensure_ascii=False)
            self.status_label.setText(f"Data eksporteret inkl. metadata og vejledninger: {filename}")
        except:
            self.status_label.setText("Fejl ved eksport af JSON.")

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #11111b; }
            QWidget { color: #cdd6f4; font-family: 'Segoe UI'; }
            QLabel#header { font-size: 24px; font-weight: bold; color: #cba6f7; }
            QLabel#score_label { font-weight: bold; }
            QTextBrowser { background-color: #1e1e2e; border: 1px solid #313244; border-radius: 8px; padding: 15px; }
            QPushButton { background-color: #cba6f7; color: #11111b; border: none; border-radius: 6px; padding: 12px; font-weight: bold; font-size: 14px; }
            QPushButton:hover { background-color: #b4befe; }
            QPushButton:disabled { background-color: #313244; color: #6c7086; }
            QProgressBar { border: 1px solid #313244; border-radius: 4px; background-color: #181825; height: 12px; }
            QProgressBar::chunk { background-color: #cba6f7; border-radius: 3px; }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = EnterpriseSecurityApp()
    window.show()
    sys.exit(app.exec())