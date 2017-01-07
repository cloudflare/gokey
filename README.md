# gokey

[![Build Status](https://travis-ci.org/cloudflare/gokey.svg?branch=master)](https://travis-ci.org/cloudflare/gokey)

## A simple vaultless password manager in Go
**gokey** is a password manager, which does not require a password vault. Instead of storing your passwords in a vault it derives your password on the fly from your master password and supplied _realm_ string (for example, resource URL). This way you do not have to manage, backup or sync your password vault (or trust its management to a third party) as your passwords are available immediately anywhere.

#### example
```
gokey -p super-secret-master-password -r example.com
```
