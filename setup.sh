#!/bin/bash

# Create complete directory structure
mkdir -p \
  src/{modules,ui,utils,core,templates,wordlists,plugins,assets/icons} \
  tests/{unit,integration} \
  scripts \
  docs/{design,api} \
  config \
  reports/{html,pdf} \
  logs/scan_results

# Create all .ui files
ui_files=(
  main_window recon vuln_scanner brute_force 
  payload_gen exploit_exec report settings 
  logs scan_result terminal plugin_manager
  about dialog_scan_progress
)
for file in "${ui_files[@]}"; do
  touch "src/ui/${file}.ui"
done

# Create all module .py files
modules=(
  recon/vulnerability_scanner
  recon/subdomain_enum
  recon/service_detection
  exploits/exploit_db
  exploits/custom_exploits
  payloads/shell_generator
  payloads/obfuscator
  reporting/pdf_generator
  reporting/html_builder
  auth/bruteforce
  auth/hash_cracker
  network/port_scanner
  network/traffic_analyzer
  web/xss_scanner
  web/sql_injector
)
for module in "${modules[@]}"; do
  mkdir -p "src/modules/$(dirname "$module")"
  touch "src/modules/${module}.py"
done

# Create core functionality files
core_files=(
  engine scan_manager 
  plugin_handler queue_dispatcher
  result_processor event_system
)
for core in "${core_files[@]}"; do
  touch "src/core/${core}.py"
done

# Create utility files
utils=(
  logger helpers validators 
  config network crypto
  file_utils threading_utils
  osint_utils color_output
)
for util in "${utils[@]}"; do
  touch "src/utils/${util}.py"
done

# Create supporting files
touch src/main.py
touch src/__init__.py
touch src/__version__.py

# Create test structure
for test in unit integration; do
  touch "tests/${test}/test_"{recon,exploits,payloads,auth,network,web}".py"
done

# Create documentation files
touch docs/{design/architecture.md,api/rest_api.md,usage.md}

# Create config files
touch config/{default.yaml,logging.conf,rulesets.json}

# Create asset files
touch src/assets/icons/{app,scan,report,exploit}.png

# Create wordlists
touch src/wordlists/{passwords_top1000.txt,subdomains_common.txt,usernames_common.txt}

# Create template files
touch src/templates/{report_base.html,email_template.html,vulnerability_card.html}

# Create plugin examples
touch src/plugins/__init__.py
touch src/plugins/example_plugin.py

# Create execution scripts
cat > scripts/run_gui.sh << 'EOF'
#!/bin/bash
source ../.venv/bin/activate
python ../src/main.py
EOF

cat > scripts/run_cli.sh << 'EOF'
#!/bin/bash
source ../.venv/bin/activate
python ../src/cli.py "$@"
EOF

chmod +x scripts/*.sh

# Create special files
touch .env.example
touch Dockerfile
touch requirements-dev.txt