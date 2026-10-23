# Thunderbird Phishing Guard (Upgraded)

MailExtension for Mozilla Thunderbird that:

- scans all incoming emails automatically;
- checks whether any inbox email was not scanned;
- scans missed emails on startup and every 5 minutes.

---

## 🛡️ Two-Stage Threat Analysis

### Stage 1: Fast Client-Side Static Analysis (JS)
The extension applies an instant client-side static check directly inside Thunderbird:
- **Header anomalies:** From vs Reply-To mismatch.
- **Display Name Spoofing:** Detects when display names contain well-known brands (Paypal, Google, Microsoft, banks, etc.) but senders use public email domains (gmail, yandex, etc.).
- **Precise SPF/DKIM/DMARC analysis:** Parses the `Authentication-Results` and `Received-SPF` headers specifically for `fail` or `softfail` results rather than doing simple substring matches.
- **Domain Alignment Check:** Compares the corporate domain of the sender with the domains of all links inside the email body (excluding public/trusted domains). Mismatches are flagged.
- **Phishing keywords:** Scans body text for urgency or suspension keywords.
- **Dangerous extensions:** Flags suspicious attachment extensions.

Each message gets an initial risk class:
- `CLEAN`
- `SUSPICIOUS`
- `MALICIOUS`

---

### Stage 2: Deep Server-Side Forensic Analysis (Python Integration)
If the initial static scan flags the message as suspicious/malicious **OR** if the email contains any attachments:
1. The extension automatically fetches the raw MIME email (EML) via `browser.messages.getRaw()`.
2. It sends the EML asynchronously to the local Python integration host via the **Native Messaging** protocol.
3. The Python host runs the full **7-level deep analysis**:
   - Extraction of all attachments (including Outlook `winmail.dat` TNEF parsing).
   - Dynamic YARA signature scanning on attachments.
   - Deep PDF structure scan (for JS injection, `/OpenAction`, `/Launch`).
   - Deep MS Office Document scan (OMSA VBA macro decompiler, P-code stomping analysis, CVE-2017-11882 exploit detection).
   - Deep Image forensics (for trailing payload data, hidden NTLM-leak links).
4. The host returns the rich structured forensic report to Thunderbird, which elevates the verdict and adds precise descriptions of discovered threats.

---

## 🚀 Installation & Setup

### Step 1: Register the Python Native Messaging Host (Windows)
To allow Thunderbird to securely communicate with the local Python script, you must register it in the Windows registry:

1. Open **PowerShell** as Administrator (or standard user if you only want to register it for the current user).
2. Run the registration script from the extension directory:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process
   & ".\register_native_host.ps1"
   ```
This automatically registers the Native Host manifest with Thunderbird.

### Step 2: Load the Extension in Thunderbird
1. Open **Thunderbird**.
2. Go to `Tools -> Add-ons and Themes` (or click Application Menu -> `Add-ons and Themes`).
3. Click the gear icon ⚙️ on the Add-ons page and select **Debug Add-ons**.
4. Click **Load Temporary Add-on...** under Temporary Extensions.
5. Select `manifest.json` from the `03_Clients_and_Integrations/ThunderbirdPhishingGuard` directory.

---

## 📁 File Structure

- `manifest.json` - extension metadata, permissions (including `nativeMessaging`)
- `background.js` - main scan engine (implements display name spoofing, alignment, auth results parsing and Native Messaging client)
- `thunderbird_phishing_guard.json` - Native Messaging Host Manifest (points to launcher)
- `thunderbird_phishing_guard.bat` - Windows launcher for the Python script
- `thunderbird_phishing_host.py` - Native Messaging Host (safely bridges Thunderbird with the `PhishingOrchestrator`)
- `register_native_host.ps1` - PowerShell automation script to add required registry entries

---

## 🔒 Security & Safety Notes

- **Communication Safety:** The Native Messaging host redirects standard stdout/stderr streams during python orchestrator runs, ensuring third-party diagnostic prints do not corrupt the message exchange protocol.
- **Client Sandbox:** The Python backend executes in user space, while the Thunderbird JS script remains sandboxed, ensuring standard security boundaries are maintained.
