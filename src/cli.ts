#!/usr/bin/env node

import { Argument, Option, program } from '@commander-js/extra-typings'
import { createReadStream, createWriteStream } from 'node:fs'
import { pipeline } from 'node:stream/promises'
import { SSHAgentClient } from './lib/ssh_agent_client.js'

program
  .name('ssh-crypt')
  .description('Encrypt/Decrypt a file with your ssh-agent private key')
  .addArgument(new Argument('<command>', 'action').choices(['encrypt', 'decrypt']))
  .option('-i, --input <path>', 'input path (default to stdin)')
  .addOption(new Option('--encryptEncoding <encoding>', 'encrypt output encoding').choices(['hex', 'base64']))
  .option('-o, --output <path>', 'output path (default to stdout)')
  .addOption(new Option('--decryptEncoding <encoding>', 'decrypt input encoding').choices(['hex', 'base64']))
  .requiredOption('-k, --key <string>', 'select the first matching pubkey in the ssh-agent')
  .requiredOption('-s, --seed <string>', 'is used to generate the secret')
  .action(async (action, options) => {
    try {
      const agent = new SSHAgentClient({ timeout: 10000 })
      const key = await agent.getIdentity(options.key)
      if (!key) {
        program.error(`Error: no SSH key found for "${options.key}"`)
      }
      const readable = options.input ? createReadStream(options.input) : process.stdin
      const writable = options.output ? createWriteStream(options.output) : process.stdout
      const getTransform =
        action === 'decrypt'
          ? agent.getDecryptTransform(key, options.seed, options.decryptEncoding)
          : agent.getEncryptTransform(key, options.seed, options.encryptEncoding)
      await getTransform.then(transform => pipeline(readable, transform, writable))
    } catch (err) {
      const error = err as Error
      if ('code' in error && error.code === 'ERR_OSSL_BAD_DECRYPT') {
        program.error("Bad secret or key, can't decrypt")
      } else {
        program.error(`Error: ${error.message}`)
      }
    }
  })

program.parse()
