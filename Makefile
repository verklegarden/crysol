.PHONY: help
help: ## Print list of all commands
	@echo ""
	@echo " ██████ ██████  ██    ██ ███████  ██████  ██		 "
	@echo "██      ██   ██  ██  ██  ██      ██    ██ ██		 "
	@echo "██      ██████    ████   ███████ ██    ██ ██		 "
	@echo "██      ██   ██    ██         ██ ██    ██ ██		 "
	@echo " ██████ ██   ██    ██    ███████  ██████  ███████ "
	@echo ""
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-50s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run full test suite
	@forge test

.PHONY: test-intense
test-intense: ## Run full test suite with intense fuzzing
	@FOUNDRY_PROFILE=intense forge test

.PHONY: coverage
coverage: ## Update coverage report and open lcov web interface
	@rm -rf coverage
	@forge coverage --report lcov
	@genhtml --branch-coverage --output "coverage" lcov.info
	@open coverage/index.html

.PHONY: fmt
fmt: ## Forge fmt complete project
	@forge fmt
	@forge fmt ./examples/

