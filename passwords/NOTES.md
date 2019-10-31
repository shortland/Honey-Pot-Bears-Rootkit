# Ilan's notes

## The /etc/passwd File

Anyone can read this file.

If a password field contains x, look in the shadow file. If it's empty, then the user can login without a password.

```sh
ilankleiman:x:1000:1000:IlanKleiman,,6464643484,6464643484:/home/ilankleiman:/usr/bin/zsh
```

```sh
name, password, user ID, group ID, gecos, home directory and shell
```

## The /etc/shadow File

Must be root to read this file.

```sh
ilankleiman:$6$05aOWPp/$jG7jbgt5gRklYpHI7kr8YTte6XT1KSpaRXhXh/V.49XiQMyf2PNcnprpzopSO4EE/wPVoPUD0wZvLTN1Q3LjV/:17210:0:99999:7:::
```

```sh
name, encrypted password, days since Jan 1 1970 that pw was changed, minimum days b/w pw changes, maximum days pw is valid, num of days before warned to change pw, num days after pw expires that account is disabled, days since Jan 1 1970 that an account is disabled
```

Encrypted password types:

```sh
$1$ is MD5
$2a$ is Blowfish
$2y$ is Blowfish
$5$ is SHA-256
$6$ is SHA-512
```
