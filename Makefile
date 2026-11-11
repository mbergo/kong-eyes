SHELL := /bin/bash
DESTINATION ?= grafana
SUITES ?= prompt-guard fixture fixture-detect fixture-leak short-circuit
.PHONY: up down logs run-suites run-chain agreement perf-probes run-kimi doctor smoke test-unit perf clean dashboard test-integration

up:            ## setup + start (DESTINATION=grafana|splunk|both; add STUB=1 for a local HEC stub)
	scripts/setup.sh --destination $(DESTINATION) $(if $(STUB),--with-splunk-stub,)
down:
	docker compose --profile grafana --profile splunk-stub --profile tools down
clean:
	docker compose --profile grafana --profile splunk-stub --profile tools down -v
logs:
	docker compose logs -f kong evaluator
run-suites:    ## run all labeled suites through Kong -> evaluator
	docker compose run --rm runner $(foreach s,$(SUITES),--suite cases/$(s).yaml) --settle 6
run-chain:     ## ordinary traffic through the probed chain, then print the signals
	docker compose run --rm runner --suite cases/chain.yaml --suite cases/chain-gap.yaml --passive --settle 6
agreement:     ## probe trail vs Kong's request-debug trace on blocked requests
	docker compose run --rm runner --suite cases/chain.yaml --suite cases/fixture.yaml --suite cases/prompt-guard.yaml --settle 6 >/dev/null; curl -fsS "http://localhost:$${EVALUATOR_PORT:-8800}/passive/agreement" | python3 -m json.tool
perf-probes:
	scripts/perf-probes.sh
run-kimi:      ## real provider suite (needs KIMI_API_KEY)
	docker compose run --rm runner --suite cases/kimi.yaml --settle 6
edge:          ## correlation edge cases (expects exit 2 = unmatched)
	docker compose run --rm runner --suite cases/edge-cases.yaml --settle 6 ; true
doctor:
	scripts/doctor.sh
smoke:
	curl -fsS -X POST "http://localhost:$${EVALUATOR_PORT:-8800}/smoke?wait_s=20" | python3 -m json.tool
test-unit:
	cd evaluator && python3 -m pytest -q tests
perf:
	scripts/perf.sh
dashboard:
	python3 observability/grafana/build_dashboard.py

test-integration:   ## needs the stack up; KE_ENV_FILE points at its .env (default ./.env)
	python3 -m pytest -q tests/integration
