.PHONY: sniff test coverage

GO_DIR = go

build:
	cd $(GO_DIR) && go build -buildmode=c-shared -o sr25519.so . && mv sr25519.so ../src/Crypto/sr25519.so

coverage: vendor/autoload.php
	XDEBUG_MODE=coverage vendor/bin/phpunit --verbose --coverage-text

test: vendor/autoload.php
	vendor/bin/phpunit --verbose

vendor/autoload.php:
	composer install --no-interaction --prefer-dist