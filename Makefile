.PHONY: sniff test coverage

coverage: vendor/autoload.php
	XDEBUG_MODE=coverage vendor/bin/phpunit --verbose --coverage-text

test: vendor/autoload.php
	vendor/bin/phpunit --verbose

vendor/autoload.php:
	composer install --no-interaction --prefer-dist