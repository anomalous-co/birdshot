PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=birdshot
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# End-to-end test: a real quack CLIENT talking to a real quack SERVER that has
# birdshot wired in as quack_authentication_function / quack_authorization_function
# (exactly as the gateway does), replaying every authorize assertion from
# test/sql/birdshot.test over the wire. quack is NOT compiled into the C++
# unittest binary, so this can't run under `make test`; it runs on the monorepo's
# Node runtime instead. Build the extension first (`make release`).
.PHONY: test-e2e
test-e2e:
	cd .. && BIRDSHOT_EXTENSION_PATH=${PROJ_DIR}build/release/extension/birdshot/birdshot.duckdb_extension \
		node_modules/.bin/tsx birdshot/test/e2e/birdshot.e2e.ts
