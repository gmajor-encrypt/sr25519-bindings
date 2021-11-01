# sr25519-bindings

PHP bindings for the GOLANG implementation of the sr25519 cryptography library

Reference to https://github.com/ChainSafe/go-schnorrkel

## Installation

```sh
composer require gmajor/sr25519-bindings
```

## Building

### Requirement

1. PHP 7 >= 7.4.0, PHP 8 FFI support 
2. GOLANG (>1.15)

### Build

```bash
cd go && go build -buildmode=c-shared -o sr25519.so . && mv sr25519.so ../src/Crypto/sr25519.so
```


## Basic Usage

### Autoloading

Codec supports `PSR-4` autoloaders.

```php
<?php
# When installed via composer
require_once 'vendor/autoload.php';
```


### KeyPair

Init a sr25519 KeyPair

```php
<?php
use Crypto\sr25519;
$sr = new sr25519();
$secretSeed = "...";
$pair = $sr->InitKeyPair("{$secretSeed}");
```

### sign message

You can sign a message by passing the message

```php
<?php
use Crypto\sr25519;
$sr = new sr25519();
$sr->Sign($sr->InitKeyPair("secretSeed"), "msg");
```


### verify signature

Verify a signature proof

```php
<?php
use Crypto\sr25519;
$sr = new sr25519();
$sr->VerifySign($sr->InitKeyPair("secretSeed"), "helloworld", "signature");
```


## Test

```
make test
```


## Resources

- [go-schnorrkel](https://github.com/ChainSafe/go-schnorrkel)


## License

The package is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT)