# Makefile
.DEFAULT_GOAL := demo

.PHONY: demo build run open-url wait-url

URL := https://localhost:9000/rhsm-client
WAIT_TIMEOUT := 60   # seconds

demo:
	@echo "==> Building…"
	@sh build.sh
	@echo "==> Starting containers (detached)…"
	@docker compose up -d
	@$(MAKE) wait-url
	@$(MAKE) open-url
	@echo "==> Streaming logs (Ctrl-C to stop)…"
	@docker compose logs -f
	@echo "==> Containers stopped; bringing stack down…"
	@docker compose down || true
	@echo "==> Done"

build:
	@echo "==> Building…"
	@sh build.sh

start:
	@echo "==> Stopping existing stack (if any)…"
	@docker compose down || true
	@echo "==> Starting containers (detached)…"
	@docker compose up -d
	@$(MAKE) wait-url
	@$(MAKE) open-url
	@echo "==> Streaming logs (Ctrl-C to stop)…"
	@docker compose logs -f
	@echo "==> Containers stopped; bringing stack down…"
	@docker compose down || true
	@echo "==> Done"

# Wait until the URL responds successfully (follows redirects, ignores self-signed certs).
wait-url:
	@URL="$(URL)"; \
	TIMEOUT="$(WAIT_TIMEOUT)"; \
	echo "==> Waiting for $$URL (timeout $${TIMEOUT}s)…"; \
	for i in `seq 1 $$TIMEOUT`; do \
	  if curl -k -s -L --fail -o /dev/null "$$URL"; then \
	    echo "==> Service is up."; \
	    exit 0; \
	  fi; \
	  sleep 1; \
	done; \
	echo "!! Timed out waiting for $$URL (continuing anyway)"; \
	exit 0

# Cross-platform opener: Windows / WSL / Linux / macOS
open-url:
	@URL="$(URL)"; \
	if [ "$$OS" = "Windows_NT" ]; then \
	  cmd.exe /c start "" "$$URL" >/dev/null 2>&1 || \
	  powershell.exe -NoProfile -Command "Start-Process '$$URL'" >/dev/null 2>&1 || true; \
	elif grep -qi microsoft /proc/version 2>/dev/null; then \
	  powershell.exe -NoProfile -Command "Start-Process '$$URL'" >/dev/null 2>&1 || true; \
	elif command -v xdg-open >/dev/null 2>&1; then \
	  xdg-open "$$URL" >/dev/null 2>&1 || true; \
	elif command -v open >/dev/null 2>&1; then \
	  open "$$URL" >/dev/null 2>&1 || true; \
	else \
	  echo "Please open $$URL in your browser."; \
	fi
