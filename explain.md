## ✅ FILE CREATION & IMPLEMENTATION ORDER

### 📦 **1. Project Bootstrap**
Start with config & logging so the rest of the app has a solid foundation.

| Priority | File | Purpose |
|---------|------|---------|
| 1️⃣ | `src/__version__.py` | Define the version string |
| 2️⃣ | `config/default.yaml` | Default settings, paths, timeouts |
| 3️⃣ | `config/logging.conf` | Structured logging |
| 4️⃣ | `src/utils/config.py` | Config loading logic |
| 5️⃣ | `src/utils/logger.py` | Logging setup with rotating files |

---

### ⚙️ **2. Core Infrastructure**
Lay down the *heart of the engine* before modules or GUI.

| Priority | File | Purpose |
|---------|------|---------|
| 6️⃣ | `src/core/event_system.py` | Signal/event pub-sub framework |
| 7️⃣ | `src/core/engine.py` | Central coordination layer |
| 8️⃣ | `src/core/scan_manager.py` | Manages scan lifecycles |
| 9️⃣ | `src/core/queue_dispatcher.py` | Queue & async task control |
| 🔟 | `src/core/plugin_handler.py` | Plugin loader/executor |
| 1️⃣1️⃣ | `src/core/result_processor.py` | Processes and stores scan output |

---

### 🧰 **3. Utilities**
Create base helpers and validators — useful everywhere.

| Priority | File | Purpose |
|---------|------|---------|
| 1️⃣2️⃣ | `src/utils/helpers.py` | Common utilities like path handling |
| 1️⃣3️⃣ | `src/utils/validators.py` | Input validation logic |
| 1️⃣4️⃣ | `src/utils/threading_utils.py` | Thread-safe wrappers |
| 1️⃣5️⃣ | `src/utils/file_utils.py` | File reading/writing safely |
| 1️⃣6️⃣ | `src/utils/network.py` | HTTP, socket utils |
| 1️⃣7️⃣ | `src/utils/crypto.py` | Hashing, encryption support |
| 1️⃣8️⃣ | `src/utils/color_output.py` | Optional CLI color printer |
| 1️⃣9️⃣ | `src/utils/osint_utils.py` | OSINT helpers (for recon later) |

---

### 🧠 **4. Module: Recon & Networking (First Implementations)**
These are lightweight and validate your engine + threading + output pipeline.

| Priority | File | Purpose |
|---------|------|---------|
| 2️⃣0️⃣ | `src/modules/recon/subdomain_enum.py` | Subdomain enum using DNS/OSINT |
| 2️⃣1️⃣ | `src/modules/network/port_scanner.py` | Threaded TCP/UDP port scanner |
| 2️⃣2️⃣ | `src/modules/network/traffic_analyzer.py` | Packet sniffing (scapy/tshark) |
| 2️⃣3️⃣ | `src/modules/recon/service_detection.py` | Detect running services & banners |

---

### 🧪 **5. Test the Engine**
Once those are in, add quick test hooks.

| Priority | File | Purpose |
|---------|------|---------|
| 2️⃣4️⃣ | `tests/unit/test_recon.py` | Verify subdomain enum works |
| 2️⃣5️⃣ | `tests/unit/test_network.py` | Validate scanner logic |

---

### 🎨 **6. GUI (.ui + PyQt Integration)**
After core + basic modules are working, design UI and link it up.

| Priority | File | Purpose |
|---------|------|---------|
| 2️⃣6️⃣ | `src/ui/main_window.ui` | Main window base layout |
| 2️⃣7️⃣ | `src/main.py` | Load the `.ui`, launch GUI |
| 2️⃣8️⃣ | `src/ui/recon.ui` | Tab/page for recon |
| 2️⃣9️⃣ | `src/ui/vuln_scanner.ui` | Placeholder for vuln scanning |
| 3️⃣0️⃣ | `src/ui/logs.ui` | Scan results/logs panel |
| 3️⃣1️⃣ | `src/ui/scan_result.ui` | Show detailed scan results |
| 3️⃣2️⃣ | `src/ui/settings.ui` | Change scan depth, targets |

---

### 🔐 **7. Auth & Web Modules**
Now add vulnerability discovery logic.

| Priority | File | Purpose |
|---------|------|---------|
| 3️⃣3️⃣ | `src/modules/auth/bruteforce.py` | SSH, FTP, etc. bruteforce |
| 3️⃣4️⃣ | `src/modules/auth/hash_cracker.py` | Offline hash cracker |
| 3️⃣5️⃣ | `src/modules/web/xss_scanner.py` | Form-based XSS scanning |
| 3️⃣6️⃣ | `src/modules/web/sql_injector.py` | Classic SQLi detection |

---

### 💥 **8. Payloads & Exploits**
After vulnerabilities are found, trigger payloads and test exploits.

| Priority | File | Purpose |
|---------|------|---------|
| 3️⃣7️⃣ | `src/modules/payloads/shell_generator.py` | Generate reverse/bind shells |
| 3️⃣8️⃣ | `src/modules/payloads/obfuscator.py` | Evade AV detection |
| 3️⃣9️⃣ | `src/modules/exploits/exploit_db.py` | Use Exploit-DB/Metasploit-like modules |
| 4️⃣0️⃣ | `src/modules/exploits/custom_exploits.py` | Local handmade POCs |

---

### 🧾 **9. Reporting & Templates**
Wrap up with professional output.

| Priority | File | Purpose |
|---------|------|---------|
| 4️⃣1️⃣ | `src/modules/reporting/html_builder.py` | Builds HTML report |
| 4️⃣2️⃣ | `src/modules/reporting/pdf_generator.py` | Converts HTML → PDF |
| 4️⃣3️⃣ | `src/templates/report_base.html` | Base layout for HTML reports |
| 4️⃣4️⃣ | `src/templates/vulnerability_card.html` | Individual vuln entry |
| 4️⃣5️⃣ | `src/templates/email_template.html` | For emailing reports (if needed) |

---

### 🧪 **10. Final Testing & CLI**
Clean it all up, make it usable without GUI.

| Priority | File | Purpose |
|---------|------|---------|
| 4️⃣6️⃣ | `src/cli.py` | CLI mode for headless scans |
| 4️⃣7️⃣ | `tests/integration/test_exploits.py` | Test exploits flow |
| 4️⃣8️⃣ | `tests/unit/test_web.py` | Test for XSS/SQLi modules |
| 4️⃣9️⃣ | `docs/usage.md` | User manual |
| 5️⃣0️⃣ | `Dockerfile`, `.env.example` | Deployment & env setup |

---

## 🔄 Suggested Loop
Once Phase 4 (modules) begins, use this dev cycle:
1. Pick a module → implement logic
2. Connect to `scan_manager`
3. Add GUI tab (optional)
4. Write a test
5. Check output in logs
