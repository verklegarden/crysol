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

.PHONY: build
build: ## Build project
	@forge build

.PHONY: clean
clean: ## Clean build artifacts
	@forge clean

.PHONY: test
test: ## Run full test suite
	@forge test --show-progress

.PHONY: test-intense
test-intense: ## Run full test suite with intense fuzzing
	@FOUNDRY_PROFILE=intense forge test --show-progress

.PHONY: test-summary
test-summary: ## Print summary of test suite
	@forge test --summary --show-progress

.PHONY: coverage
coverage: ## Update coverage report and print summary
	@forge coverage --report lcov
	@forge coverage --report summary

# Note that ripgrep instead of grep is used.
# See https://github.com/BurntSushi/ripgrep.
.PHONY: todos
todos: ## Grep TODO's in src/ and test/
	@rg -rn "TODO" src/ test/

.PHONY: examples
examples: ## Run examples
	@echo "########################################"
	@echo "##"
	@echo "##   Random"
	@echo "##"
	@echo "########################################"
	@forge script examples/Random.sol:RandomExample -v
	@echo "########################################"
	@echo "##"
	@echo "##   Secp256k1"
	@echo "##"
	@echo "########################################"
	@forge script examples/Secp256k1.sol:Secp256k1Example -v
	@echo "########################################"
	@echo "##"
	@echo "##   ECDSA"
	@echo "##"
	@echo "########################################"
	@forge script examples/signatures/ECDSA.sol:ECDSAExample -v
	@echo "########################################"
	@echo "##"
	@echo "##   Schnorr (ERC-XXX)"
	@echo "##"
	@echo "########################################"
	@forge script examples/signatures/Schnorr.sol:SchnorrExample -v

.PHONY: fmt
fmt: ## Format project
	@forge fmt
	@forge fmt ./examples/

