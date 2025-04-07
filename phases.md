## 🧭 DEVELOPMENT WORKFLOW PHASES (START → FINISH)

---

### 🟦 **Phase 1: Foundation & Bootstrapping**
> ⏳ Estimated time: 1–2 days  
> 👨‍💻 Goal: Set up basic scaffolding, environment, and configuration

| ✅ Step | Files to Work On |
|-------|------------------|
| 1. Setup Python virtual env | `.venv`, `requirements-dev.txt`, `scripts/run_gui.sh`, `scripts/run_cli.sh` |
| 2. Add `.gitignore`, `README.md` | Root directory |
| 3. Define metadata & version | `src/__version__.py`, `src/__init__.py` |
| 4. Create config loaders & logger | `src/utils/config.py`, `src/utils/logger.py`, `config/default.yaml`, `config/logging.conf` |

---

### 🟨 **Phase 2: Core Engine Development**
> ⏳ Estimated time: 3–5 days  
> 👨‍💻 Goal: Develop the backbone of the tool (scan manager, event system, plugin handler)

| ✅ Step | Files to Work On |
|-------|------------------|
| 5. Build core framework | `src/core/engine.py`, `src/core/event_system.py` |
| 6. Implement plugin system | `src/core/plugin_handler.py`, `src/plugins/` |
| 7. Add scan orchestration logic | `src/core/scan_manager.py`, `src/core/queue_dispatcher.py`, `src/core/result_processor.py` |
| 8. Write reusable helpers | `src/utils/helpers.py`, `src/utils/validators.py`, `src/utils/threading_utils.py` |

---

### 🟩 **Phase 3: UI Integration with PyQt6**
> ⏳ Estimated time: 3–4 days  
> 🎨 Goal: Connect backend logic with GUI using .ui files

| ✅ Step | Files to Work On |
|--------|------------------|
| 9. Design all `.ui` files | `src/ui/*.ui` (use Qt Designer) |
| 10. Connect main GUI to engine | `src/main.py`, `src/ui/main_window.ui`, controller classes |
| 11. Setup modular tabs/panels | e.g. `recon.ui`, `vuln_scanner.ui`, `logs.ui` |

---

### 🟥 **Phase 4: Modules Implementation (Phase-wise)**
> ⏳ Estimated time: ~2 weeks  
> 🧠 Goal: Build each module in isolation & then plug into core

| 📌 Category | Module Files |
|------------|--------------|
| 🔍 Recon | `src/modules/recon/*.py` |
| 🔓 Auth & Brute Force | `src/modules/auth/*.py` |
| 🌐 Network Scans | `src/modules/network/*.py` |
| 🌐 Web Exploits | `src/modules/web/*.py` |
| 💥 Exploits | `src/modules/exploits/*.py` |
| 🧬 Payloads | `src/modules/payloads/*.py` |
| 📊 Reporting | `src/modules/reporting/*.py`, `src/templates/*.html` |

✅ Each module:
- Uses helper functions from `src/utils/`
- Communicates with `scan_manager`
- Emits events to GUI or writes logs

---

### 🟪 **Phase 5: Utility Enhancement & Wordlist Integration**
> ⏳ Estimated time: 2–3 days  
> 🛠️ Goal: Add utilities to support main modules & wordlist support

| ✅ Step | Files to Work On |
|--------|------------------|
| 12. Cryptographic & network helpers | `src/utils/crypto.py`, `src/utils/network.py`, `src/utils/file_utils.py` |
| 13. Add colorized output | `src/utils/color_output.py` |
| 14. Integrate wordlists | `src/wordlists/*.txt` |

---

### 🟫 **Phase 6: CLI Tool & Automation Support**
> ⏳ Estimated time: 1–2 days  
> ⚙️ Goal: Enable headless CLI-based pentesting

| ✅ Step | Files to Work On |
|--------|------------------|
| 15. Create CLI entry point | `src/cli.py` (you may need to create it) |
| 16. Link CLI to core engine | Uses same `scan_manager` and `config` |

---

### 🟨 **Phase 7: Reporting, Export, and Logs**
> ⏳ Estimated time: 2–3 days  
> 📊 Goal: Generate reports, email alerts, logging system

| ✅ Step | Files to Work On |
|--------|------------------|
| 17. Build HTML reports | `src/modules/reporting/html_builder.py`, `src/templates/*.html` |
| 18. Export to PDF | `src/modules/reporting/pdf_generator.py` |
| 19. Implement scan logging | `logs/scan_results/`, `src/utils/logger.py` |

---

### 🟧 **Phase 8: Testing and Docs**
> ⏳ Estimated time: 2–4 days  
> ✅ Goal: Unit/integration testing, and technical docs

| ✅ Step | Files to Work On |
|--------|------------------|
| 20. Unit tests | `tests/unit/*.py` |
| 21. Integration tests | `tests/integration/*.py` |
| 22. Write usage & API docs | `docs/usage.md`, `docs/api/rest_api.md`, `docs/design/architecture.md` |

---

### 🟦 **Phase 9: Packaging, Docker, and Deployment**
> ⏳ Estimated time: 2–3 days  
> 📦 Goal: Make it portable and runnable anywhere

| ✅ Step | Files to Work On |
|--------|------------------|
| 23. Setup Docker container | `Dockerfile`, `scripts/run_cli.sh`, `.env.example` |
| 24. Prepare for PyInstaller/FPM | (optional) |
| 25. Final `README.md` polish | Add usage examples, screenshots, badges |

---

## ✅ Tips for Each Phase

- Use **type hints** and **docstrings**
- Use `asyncio` or `threading` when performance is key (e.g., scanning modules)
- Isolate **network interaction** and **file I/O**
- Always route errors to `logger`
- Follow **DRY principles**, use `utils` wherever you repeat logic