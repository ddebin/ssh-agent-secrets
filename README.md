# ssh-agent-secrets

[![CI](https://img.shields.io/github/actions/workflow/status/ddebin/ssh-agent-secrets/main.yml)](https://github.com/ddebin/ssh-agent-secrets/actions)
[![Release](https://img.shields.io/github/v/release/ddebin/ssh-agent-secrets)](https://github.com/ddebin/ssh-agent-secrets/releases)
[![License](https://img.shields.io/github/license/ddebin/ssh-agent-secrets)](./LICENSE)

> Encrypt and decrypt secrets using your SSH agent — no plaintext, no extra key management.

Inspired by [node-ssh-agent](https://github.com/mcavage/node-ssh-agent) and [ssh-crypt.bash](https://gist.github.com/davisford/2949118)

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
- 👥 Works with existing SSH agent workflows like [1Password](https://developer.1password.com/docs/ssh/agent/)

## ⚠️ Limitations

- We can't use ecdsa/ed25519 keys, they always give different signatures.

## 💻 CLI usage

```bash
npx ssh-agent-secrets --help
```

```text
Usage: ssh-crypt [options] <command> <source> [destination]

Encrypt/Decrypt a file with your ssh-agent private key

Arguments:
  command              (choices: "encrypt", "decrypt")
  source               file to encrypt
  destination          output path (default to stdout)

Options:
  -k, --key <string>   select the first matching pubkey in the ssh-agent
  -s, --seed <string>  is used to generate the secret
  -h, --help           display help for command
```

## 🛠️ Library installation

```bash
npm i ssh-agent-secrets
```

### Sample

```javascript
import { SSHAgentClient } from 'ssh-agent-secrets'

const agent = new SSHAgentClient()
const identity = await agent.getIdentity('AWS')
if (!identity) {
  throw new Error()
}

const encrypted = await agent.encrypt(
  identity,
  'not_a_secret_but_a_seed',
  Buffer.from('Lorem ipsum dolor', 'utf8'),
)
console.log('Encrypted data:', encrypted)

const decrypted = await agent.decrypt(
  identity,
  'not_a_secret_but_a_seed',
  encrypted,
)
console.log('Decrypted data:', decrypted.toString('utf8'))
```
