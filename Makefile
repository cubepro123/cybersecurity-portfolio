PYTHON ?= python
PROJECT_DIRS := projects/python-network-scanner projects/linux-log-analyzer projects/file-integrity-monitor projects/secure-login-demo
TEST_DIRS := $(addsuffix /tests,$(PROJECT_DIRS))

.PHONY: test compile check

test:
	$(PYTHON) -m pytest -q $(TEST_DIRS)

compile:
	$(PYTHON) -m compileall $(PROJECT_DIRS)

check: compile test
