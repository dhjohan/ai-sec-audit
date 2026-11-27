# AI Code Security Benchmark - Phase 0 driver
.PHONY: help check-env build-eval-image lock-env test lint typecheck codeql-offline clean sandbox-up sandbox-down sandbox-logs

help:
	@echo "AI Code Security Benchmark"
	@echo ""
	@echo "Phase 0 targets:"
	@echo "  check-env      Capture local lockfile hashes into versions.lock.json"
	@echo "  build-eval-image  Build the evaluation Docker image"
	@echo "  lock-env       Capture actual tool versions from the built image"
	@echo ""
	@echo "Verification targets:"
	@echo "  test           Run harness + sandbox tests in an isolated container"
	@echo "  lint           Ruff + mypy on trusted source only"
	@echo "  typecheck      mypy on trusted source only"
	@echo "  codeql-offline Offline CodeQL resolve check (no network, read-only root)"
	@echo "  clean          Remove caches only (never artifacts/)"
	@echo ""
	@echo "Sandbox targets:"
	@echo "  sandbox-up     Start the sandbox template dev server"
	@echo "  sandbox-down   Stop the sandbox template"
	@echo "  sandbox-logs   Follow sandbox logs"

# Phase 0a: capture hashes of inputs that the image build consumes.
check-env:
	@python pipeline/lock_env.py pre

build-eval-image: check-env
	docker build -f docker/Dockerfile.eval -t ai-sec-eval:latest .

# Phase 0b: record the versions actually installed in the pinned image.
lock-env: build-eval-image
	@docker run --rm --workdir /tmp ai-sec-eval:latest sh -c '\
		echo "python=$$(python --version 2>&1)"; \
		echo "semgrep=$$(semgrep --version)"; \
		echo "codeql=$$(codeql version --format=terse)"; \
		echo "pip_audit=$$(pip-audit --version)"; \
		echo "ruff=$$(ruff --version)"; \
		echo "mypy=$$(mypy --version)"; \
		echo "pytest=$$(pytest --version)"' > /tmp/tool_versions.txt
	@docker run --rm --workdir /tmp ai-sec-eval:latest \
		codeql resolve packs --format=json > /tmp/codeql_packs.json
	@python pipeline/lock_env.py post /tmp/tool_versions.txt /tmp/codeql_packs.json

# Untrusted generated code runs sandboxed: no network, read-only root, capped.
test: lock-env
	docker run --rm \
		--network=none \
		--read-only \
		--tmpfs /tmp:rw,size=64m \
		--tmpfs /workspace/artifacts:rw,size=128m \
		--cap-drop=ALL \
		--memory=512m \
		--cpus=1 \
		-v $(CURDIR)/sandbox_template:/workspace/sandbox_template:ro \
		-v $(CURDIR)/pipeline:/workspace/pipeline:ro \
		-v $(CURDIR)/analysis:/workspace/analysis:ro \
		-v $(CURDIR)/tests_harness:/workspace/tests_harness:ro \
		-v $(CURDIR)/corpus:/workspace/corpus:ro \
		-v $(CURDIR)/rules:/workspace/rules:ro \
		-v $(CURDIR)/taxonomies:/workspace/taxonomies:ro \
		ai-sec-eval:latest \
		sh -c "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace pytest -p no:cacheprovider /workspace/tests_harness -v --tb=short \
		&& rm -rf /tmp/sandbox_template \
		&& cp -R /workspace/sandbox_template /tmp/sandbox_template \
		&& PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/tmp/sandbox_template pytest -p no:cacheprovider /tmp/sandbox_template/tests -v --tb=short"
	# Calibrate every corpus fixture (secure/vuln + the full Semgrep suite)
	# offline. The source tree is read-only, so copy it into the /tmp tmpfs.
	docker run --rm \
		--network=none \
		--read-only \
		--tmpfs /tmp:rw,size=256m \
		--cap-drop=ALL \
		--memory=1g \
		--cpus=1 \
		-v $(CURDIR)/sandbox_template:/workspace/sandbox_template:ro \
		-v $(CURDIR)/pipeline:/workspace/pipeline:ro \
		-v $(CURDIR)/corpus:/workspace/corpus:ro \
		-v $(CURDIR)/rules:/workspace/rules:ro \
		-v $(CURDIR)/taxonomies:/workspace/taxonomies:ro \
		ai-sec-eval:latest \
		sh -c "mkdir -p /tmp/workspace /tmp/home \
		&& cp -R /workspace/pipeline /tmp/workspace/pipeline \
		&& cp -R /workspace/corpus /tmp/workspace/corpus \
		&& cp -R /workspace/rules /tmp/workspace/rules \
		&& cp -R /workspace/taxonomies /tmp/workspace/taxonomies \
		&& cp -R /workspace/sandbox_template /tmp/workspace/sandbox_template \
		&& cd /tmp/workspace \
		&& HOME=/tmp/home PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/tmp/workspace/sandbox_template:/tmp/workspace python -m pipeline.calibrate"

# Phase 3 readiness: the pinned pack must resolve as evaluser with no network and
# a read-only root. Only the /tmp tmpfs is writable.
codeql-offline: build-eval-image
	docker run --rm \
		--network=none \
		--read-only \
		--tmpfs /tmp:rw,size=64m \
		--cap-drop=ALL \
		--memory=512m \
		--cpus=1 \
		--workdir /tmp \
		ai-sec-eval:latest \
		sh -c 'mkdir -p /tmp/codeql-cache \
			&& test -w /tmp/codeql-cache \
			&& test -w "$$HOME/.codeql/compile-cache" \
			&& codeql resolve packs >/dev/null \
			&& codeql resolve queries "codeql/python-queries@1.7.2:codeql-suites/python-security-extended.qls" >/dev/null \
			&& echo "codeql offline resolve OK"'

lint: lock-env
	docker run --rm \
		--network=none \
		--read-only \
		--tmpfs /tmp:rw,size=64m \
		--tmpfs /workspace/.ruff_cache:rw,size=32m \
		--tmpfs /workspace/.mypy_cache:rw,size=32m \
		--cap-drop=ALL \
		--memory=512m \
		--cpus=1 \
		-v $(CURDIR)/pipeline:/workspace/pipeline:ro \
		-v $(CURDIR)/analysis:/workspace/analysis:ro \
		-v $(CURDIR)/tests_harness:/workspace/tests_harness:ro \
		-v $(CURDIR)/sandbox_template/app:/workspace/sandbox_template/app:ro \
		-v $(CURDIR)/sandbox_template/pyproject.toml:/workspace/pyproject.toml:ro \
		ai-sec-eval:latest \
		sh -c "ruff check --no-cache /workspace/pipeline /workspace/analysis /workspace/tests_harness /workspace/sandbox_template/app && mypy --cache-dir=/tmp/.mypy_cache /workspace/pipeline /workspace/analysis /workspace/tests_harness /workspace/sandbox_template/app"

typecheck: lock-env
	docker run --rm \
		--network=none \
		--read-only \
		--tmpfs /tmp:rw,size=64m \
		--tmpfs /workspace/.mypy_cache:rw,size=32m \
		--cap-drop=ALL \
		--memory=512m \
		--cpus=1 \
		-v $(CURDIR)/pipeline:/workspace/pipeline:ro \
		-v $(CURDIR)/analysis:/workspace/analysis:ro \
		-v $(CURDIR)/tests_harness:/workspace/tests_harness:ro \
		-v $(CURDIR)/sandbox_template/app:/workspace/sandbox_template/app:ro \
		-v $(CURDIR)/sandbox_template/pyproject.toml:/workspace/pyproject.toml:ro \
		ai-sec-eval:latest \
		mypy --cache-dir=/tmp/.mypy_cache /workspace/pipeline /workspace/analysis /workspace/tests_harness /workspace/sandbox_template/app

# Caches only. artifacts/ is immutable raw experimental data (AGENTS.md).
clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__ build_batch codeql_dbs /tmp/tool_versions.txt /tmp/codeql_packs.json
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

sandbox-up:
	cd sandbox_template && docker compose up -d --build

sandbox-down:
	cd sandbox_template && docker compose down

sandbox-logs:
	cd sandbox_template && docker compose logs -f
