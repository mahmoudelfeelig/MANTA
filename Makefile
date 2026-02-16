.PHONY: help test-all test-backend test-ml test-android smoke

help:
	@echo "Available targets:"
	@echo "  test-backend  - run backend adapter tests"
	@echo "  test-ml       - run ml pipeline tests"
	@echo "  test-android  - run android unit tests (requires working gradle runtime)"
	@echo "  test-all      - run backend and ml tests"
	@echo "  smoke         - compile python modules"

smoke:
	python3 -m compileall backend-adapter/app backend-adapter/tests ml-pipeline/src ml-pipeline/tests

test-backend:
	cd backend-adapter && \
	python3 -m venv .venv && \
	. .venv/bin/activate && \
	pip install -e .[test] && \
	pytest -q tests

test-ml:
	cd ml-pipeline && \
	python3 -m venv .venv && \
	. .venv/bin/activate && \
	pip install -e .[test] && \
	pytest -q tests

test-android:
	gradle -p android-app :app:testDebugUnitTest

test-all: test-backend test-ml
