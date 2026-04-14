# ssh-agent-secrets

[![CI](https://img.shields.io/github/actions/workflow/status/ddebin/ssh-agent-secrets/main.yml)](https://github.com/ddebin/ssh-agent-secrets/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ddebin/ssh-agent-secrets)](https://app.codecov.io/gh/ddebin/ssh-agent-secrets)
[![NPM](https://img.shields.io/npm/v/ssh-agent-secrets)](https://www.npmjs.com/package/ssh-agent-secrets)
[![License](https://img.shields.io/github/license/ddebin/ssh-agent-secrets)](./LICENSE)

> Encrypt and decrypt secrets using your SSH agent — no plaintext, no extra key management.

Inspired by [node-ssh-agent](https://github.com/mcavage/node-ssh-agent) and [ssh-crypt.bash](https://gist.github.com/wmertens/c4f2c4186c04dc5442bbe3396f2c12f6)

## ✨ Overview

`ssh-agent-secrets` lets you encrypt and decrypt secrets using your existing SSH agent.

- No `.env` files
- No plaintext secrets
- No additional key management

A seed is used to generate the secret, it's recommended you don't use the same seed everywhere.

## ⚡ Features

- 🔐 SSH-based
- 🧩 Minimal and portable
- 🔨 Node library included to decrypt secrets on-the-fly in your code
- 📦 Safe to store encrypted secrets in Git
- `node:stream` compatible
- `sign` message / `verify` signature
- 👥 Works with existing SSH agent workflows like [1Password](https://developer.1password.com/docs/ssh/agent/) or [Bitwarden](https://bitwarden.com/help/ssh-agent/)

## ⚠️ Limitations

- Can't use ECDSA keys, they always give different signatures
- [RFC8332](https://www.rfc-editor.org/info/rfc8332) compatible agent (e.g. OpenSSH 7.6+) is mandatory to use SHA2-512 signature scheme. You can still use deprecated SHA1 signatures with `rsaSignatureFlag:0` option in `SSHAgentClient` constructor.

## 💻 CLI usage

```bash
npx ssh-agent-secrets --help
```

```text
Usage: ssh-crypt [options] <command>

Encrypt/Decrypt a file with your ssh-agent private key

Arguments:
  command                       action (choices: "encrypt", "decrypt")

Options:
  -i, --input <path>            input path (default to stdin)
  --encryptEncoding <encoding>  encrypt output encoding (choices: "hex",
                                "base64")
  -o, --output <path>           output path (default to stdout)
  --decryptEncoding <encoding>  decrypt input encoding (choices: "hex",
                                "base64")
  -k, --key <string>            select the first matching pubkey in the
                                ssh-agent
  -s, --seed <string>           is used to generate the secret
  -h, --help                    display help for command
```

## 🛠️ Library installation

```bash
npm i ssh-agent-secrets
```

### [Sample](/example/test.js)

```javascript
import { SSHAgentClient } from 'ssh-agent-secrets'

const agent = new SSHAgentClient()

const identities = await agent.getIdentities()
console.log(identities)

const identity = await agent.getIdentity('ED25519')

const encrypted = await agent.encrypt(
  identity,
  'not_a_secret_but_a_seed',
  Buffer.from('Lorem ipsum dolor', 'utf8'),
  'hex',
)
console.log('Encrypted data:', encrypted)

const decrypted = await agent.decrypt(
  identity,
  'not_a_secret_but_a_seed',
  encrypted,
  'hex',
)
console.log('Decrypted data:', decrypted.toString('utf8'))
```

### Local test

```bash
ssh-agent -D
SSH_AUTH_SOCK="[...]" ssh-add test/ssh_keys/*
SSH_AUTH_SOCK="[...]" npm run test
```
