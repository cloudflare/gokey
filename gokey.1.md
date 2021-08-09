---
date: 2018-06-06
footer: gokey
header: "Gokey's Manual"
layout: page
license: 'Licensed under the 3-clause BSD license'
section: 1
title: GOKEY
---

# NAME

gokey - A simple vaultless password manager in Go

# SYNOPSIS

**gokey** [**OPTIONS**]

# DESCRIPTION

**gokey** is a password manager, which does not require a password vault.
Instead of storing your passwords in a vault it derives your password on the fly
from your master password and supplied _realm_ string (for example, resource
URL). This way you do not have to manage, backup or sync your password vault (or
trust its management to a third party) as your passwords are available
immediately anywhere.

# OPTIONS

**-o** *output_path*
:    by default **gokey** outputs generated data to *stdout*

**-P** */path/to/password*
:    path to master password file which will be used to generate other
passwords/keys or to encrypt seed file (see *Modes of operation* below, if no
master password or master password file is provided, **gokey** will ask for it
interactively)

**-p** *master_password*
:    master password which will be used to generate other passwords/keys or to
encrypt seed file (see *Modes of operation* below, if no master password or
master password file is provided, **gokey** will ask for it interactively)

**-r** *password/key_realm*
:    any string which identifies requested password/key, most likely key usage
or resource URL

**-s** *path_to_seed_file*
:    needed, if you want to use seed file instead of master password as an
entropy source (see *Modes of operation* below); can be generated with **-t**
*seed* flag as described below

**-skip** *number_of_bytes*
:    number of bytes to skip when reading seed file

**-u**
:    **UNSAFE**, allow generating keys without using a seed file (see *Modes of
operation* below)

**-t** *password/key_type*
:    requested password/key output type. Supported password/key types:

    * *pass* - default, generates a password
    * *seed* - generates a seed file, which can be used with **-s** option later
    * *raw* - generates 32 random bytes (can be used as a symmetric key)
    * *ec256* - generates ECC P-256 private key
    * *ec384* - generates ECC P-384 private key
    * *ec521* - generates ECC P-521 private key
    * *rsa2048* - generates 2048-bit RSA private key
    * *rsa4096* - generates 4096-bit RSA private key
    * *x25519* - generates x25519 (also known as curve25519) ECC private key
    * *ed25519* - generates ed25519 ECC private key

**-l** *length*
:   number of characters in the generated password or number of bytes in the
generated raw stream (default 10 for "pass" type and 32 for "raw" type)

# MODES OF OPERATION

**gokey** can generate passwords and cryptographic private keys (ECC and RSA
keys are currently supported). However, without any additional options specified
it uses your master password as a single source of entropy for generated data.
For passwords it is acceptable most of the time, but keys usually have much
higher entropy requirements.

For cases, where higher entropy is required for generated passwords/keys,
**gokey** can use a seed file (a blob with random data) instead of the master
password as a source of entropy.

## Simple mode (without a seed file)
In simple mode passwords are derived directly from your master password and the
realm string. That is each unique combination of a master password and a realm
string will produce a unique password.

For example, if your master password is *super-secret-master-password* and you
want to generate a password for *example.com*, you would invoke **gokey** like
```
gokey -p super-secret-master-password -r example.com
```

If you need a password for a different resource, *example2.com*, you would
change the real string
```
gokey -p super-secret-master-password -r example2.com
```
This way you need to remember only your master password and you can always
recreate passwords for your services/resources.

*NOTE*: In this mode generated passwords are as strong as your master password,
so do have your master password strong enough. You can also derive private keys
from your master password, but keep in mind, that these keys will have low
entropy. That is why it is considered unsafe, so **gokey** does not allow it by
default. If you're **_really_** know what you are doing, you can override this
default by supplying **-u** flag.

## Using a seed file
If you plan to generate not only passwords, but also private keys or you want to
have your passwords/keys with higher entropy, you can use a seed file instead of
the master password. You still need to supply a master password, when invoking
**gokey**, but it will be used only to protect the seed file itself; all
generated passwords/keys will be derived from the data in the seed file.
**gokey** uses seed files protected (encrypted) with your master password, so it
is reasonably safe to store/backup seed files to a third party location, such as
Google Drive or Dropbox.

To generate an encrypted seed file, use
```
gokey -p super-secret-master-password -t seed -o seedfile
```
This will create a seed file *seedfile* with 256 bytes of random data. The data
is encrypted using AES-256-GCM mode and *super-secret-master-password* as a key.

Then, to generate EC-256 private key for *example.com*, use
```
gokey -p super-secret-master-password -s seedfile -r example.com -t ec256
```

# AUTHOR

Ignat Korchagin <ignat@cloudflare.com>
