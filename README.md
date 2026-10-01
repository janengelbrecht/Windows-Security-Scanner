Windows Security Scanner an advanced, Python-based suite of tools designed to perform in-depth security audits and remediation analysis on Windows machines.

This project is tailored for system administrators and IT security professionals who need to validate, harden, and document endpoint security based on modern "Zero Trust" principles.

📦 The Tools in this Suite
The project consists of two primary graphical applications working in tandem to secure your system from end to end:

1. systemcheck.py (Endpoint Auditor)
This is the core component that performs the actual security scanning of the computer.

What it does: The application conducts over 30 in-depth system health checks by reading the Windows Registry and executing PowerShell scripts. These checks cover hardware, identity, network, Defender, forensics, and OS services.

Output: Assigns the system an overall security score (0-100) and allows the user to export the full health report as a structured JSON file.

⚠️ Note: This process requires the program to be run with Administrator privileges to read WMI (Windows Management Instrumentation) data and secure registry keys.

2. report_analyzer.py (Remediation Analyzer)
An interactive analysis tool that loads the generated JSON report and translates the raw data into a concrete action plan.

What it does: Filters the scan data so only the identified vulnerabilities and errors are displayed in the user interface.

Proposed Solutions: Generates detailed, step-by-step guides based on a built-in database, explaining exactly how each specific error can be configured and remediated administratively.

Export: Provides the option to save a prioritized action plan as a text file (.txt) or Markdown file (.md) to hand over to the IT department.

⚙️ Preparing Your Windows PC
To run these applications, your Windows computer must have Python installed, and the system environment must be set up correctly so it can locate Python and its libraries from any directory.

Step 1: Python Installation & PATH Setup
If you do not already have Python installed, follow these exact steps:

Go to the official website: python.org/downloads/windows.

Download the latest version of Python (select "Windows installer (64-bit)").

Launch the downloaded executable (.exe).

🛑 VERY IMPORTANT: On the very first screen of the installer, check the box that says "Add python.exe to PATH" (usually located at the bottom of the window).

Why? This step adds Python to Windows' environment variables (PATH). This ensures the Command Prompt knows where to look when executing a Python command or installing a library, regardless of your current folder location.

Click "Install Now" and let the process finish.

Verify the installation: Open the Windows Command Prompt (press the Windows key, type cmd, and press Enter). Type python --version and press Enter. If the system returns a version number (e.g., Python 3.12.x), Python and PATH are configured correctly.

Step 2: Required Libraries & Installation
The programs utilize several built-in standard libraries included with your Python installation (such as sys, json, datetime, winreg, and subprocess). You do not need to do anything with these.

However, both applications feature a graphical user interface (GUI) that requires the external library PySide6 (Qt for Python). This must be downloaded and installed manually:

Open the Windows Command Prompt (cmd).

Type the following command and press Enter:
pip install PySide6

pip (Python's built-in package manager) will now connect to the internet, download PySide6, and install it on your PC. Wait until the process reports "Successfully installed".

🚀 Running the Programs
Once Python, PATH, and PySide6 are ready, you can run the suites.

Running the Scanning Tool (Endpoint Auditor):
Because systemcheck.py examines critical Windows components, it must be run as an administrator.

Press the Windows key, type cmd, right-click on "Command Prompt," and select "Run as administrator".

Use the cd command to navigate to the folder where you saved the program (e.g., cd C:\Users\YourName\Downloads).

Run the application with the command:
python systemcheck.py

Running the Analysis Tool (Remediation Analyzer):
This tool only reads a JSON file and therefore does not require administrator privileges.

Open a standard Command Prompt.

Navigate to the script's folder.

Run the application with the command:
python report_analyzer_2.py

⚠️ Disclaimer
These programs interact directly with, and advise on changes to, core Windows policies, Local Security Authority (LSA), and the Registry. Incorrect configuration of these critical elements can cause the system to become unstable or inaccessible. The tool and accompanying guides are provided "as is", and it is strongly recommended to thoroughly test all proposed changes in an isolated test environment before deploying them to a production environment.

Part 1: systemcheck.py
1. What systemcheck.py Does
This Python-based program is a graphical application designed to perform a comprehensive, enterprise-grade security audit of a Windows computer. systemcheck.py requires administrator privileges to read system WMI data and protected registry keys. Upon completing the scan, it calculates an overall security score from 0 to 100 and presents the user with a detailed system health report. If security flaws are found, the user can click a dedicated "[RESOLVE ISSUE]" link to open a specific dialog box containing detailed, step-by-step remediation instructions. Finally, it allows the entire generated report (including metadata) to be exported as a structured JSON file for documentation.

2. What systemcheck.py Examines
The application analyzes more than 30 different system policies via the registry and executes PowerShell scripts to evaluate six critical security categories:

Hardware and Core Security: Checks if modern, hardware-based protections like TPM 2.0, Secure Boot, BitLocker drive encryption, and Memory Integrity (HVCI) are enabled and configured correctly.

Identity and Access Control: Verifies that insecure, legacy password protocols (such as WDigest and LM Hash storage) are disabled, and that built-in Guest and Administrator accounts are secured against abuse.

Network and Protocols: Analyzes network security by validating that Windows Firewall profiles (Domain, Private, Public) are active, legacy protocols like SMBv1 are removed, and risky ports are closed.

Defender and Threat Protection: Confirms that Windows Defender is running optimally with Real-time Protection, Cloud-delivered Protection, Tamper Protection, and Controlled Folder Access against ransomware.

PowerShell and Forensics: Ensures the system generates the necessary logs of system activity and PowerShell commands (via Script Block Logging and Module Logging) so unauthorized events can be traced during an investigation.

OS Configuration and Services: Examines core Windows OS policies, ensuring User Account Control (UAC) is configured strictly, system telemetry is restricted, and unnecessary services like Xbox Services and Print Spooler are disabled.

3. Impact of Remediation on System Security
Fixing the identified vulnerabilities using the instructions from systemcheck.py significantly increases system resilience:

Preventing Unauthorized Access and Lateral Movement: Disabling insecure network protocols and protecting passwords in memory (e.g., via LSA Protection) prevents cybercriminals from extracting credentials and spreading to other devices on the corporate network.

Resilience Against Advanced Malware: Enforcing strict Defender policies and hardware-based core security minimizes the risk of malicious software executing, overwriting critical settings, or encrypting company data.

Improved Traceability and Incident Response: Enabling full command-line and PowerShell logging ensures IT administrators have the necessary forensic evidence to effectively analyze and halt an ongoing attack.

Minimized Attack Surface: Proactively shutting down redundant services and closing insecure ports removes the most obvious entry points for an attacker, a vital step in establishing a modern "Zero Trust" architecture.

Part 2: report_analyzer.py
1. What report_analyzer.py Does
This Python-based application ("CyberSec Pro - Remediation & Analysis Analyzer") serves as an advanced graphical analysis and remediation tool. Unlike the scanner, it loads a pre-generated JSON security report to analyze metadata and scan results. It filters the loaded data to present only the system policies and parameters that failed the security check. For every identified error, report_analyzer.py generates a detailed, step-by-step remediation guide directly in the UI. Finally, it allows the user to export a complete, easy-to-read action plan as a text or Markdown file highlighting critical vulnerabilities and providing administrative remediation instructions.

2. What report_analyzer.py Examines
The tool evaluates the imported scan data across the six main security categories, specifically highlighting the following shortcomings:

Hardware and Core Security: Analyzes data for missing hardware protections, including inactive TPM modules, disabled Secure Boot, missing BitLocker encryption, and inactive Memory Integrity.

Identity and Access Control: Investigates loaded errors regarding compromised password policies, such as allowing blank passwords, active built-in admin/guest accounts, or missing LAPS and LSA protection implementations.

Network and Protocols: Extracts network-related vulnerabilities, such as active legacy protocols (SMBv1), disabled firewalls, or systems responding on insecure ports.

Defender and Threat Protection: Highlights critical gaps in antivirus configuration, such as disabled real-time protection, lack of cloud protection, inactive Tamper Protection, and missing ransomware folder shields.

PowerShell and Forensics: Identifies weaknesses in logging mechanisms by exposing missing PowerShell Script Block and Module logging, or if insecure execution policies and legacy versions (PowerShell v2) are permitted.

OS Configuration and Services: Exposes insecure OS settings, such as running unnecessary services (Print Spooler, Xbox), allowed Autorun for USB devices, or sub-optimally configured UAC.

3. Impact of Remediation on System Security
Resolving the issues presented in the report_analyzer.py action plan is critical for system hardening:

Direct Closure of Vulnerabilities: By following the specific, step-by-step guides, administrators can patch the exact misconfigurations attackers would otherwise exploit to gain unauthorized access.

Systematic Risk Management: Because the action plan explicitly tags certain errors as critical vulnerabilities ("High Priority"), the IT department can easily prioritize their efforts and patch the most dangerous security holes first.

Minimizing the Attack Surface: Disabling redundant services, enforcing strict access controls, and updating logging policies—as dictated by the analyzer's guides—drastically reduces the system's overall exposure, making both infection and the spread of malicious software significantly harder.
