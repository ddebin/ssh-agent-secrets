#!/usr/bin/env node

import * as fs from 'fs'
import { Argument, program } from '@commander-js/extra-typings'
import { SSHAgentClient } from './lib/ssh_agent_client.js'
import { buffer, text } from 'stream/consumers'

program
  .name('ssh-crypt')
  .description('Encrypt/Decrypt a file with your ssh-agent private key')
  .addArgument(new Argument('<command>', 'action').choices(['encrypt', 'decrypt']))
  .option('-i, --input <path>', 'input path (default to stdin)')
  .option('-o, --output <path>', 'output path (default to stdout)')
  .requiredOption('-k, --key <string>', 'select the first matching pubkey in the ssh-agent')
  .requiredOption('-s, --seed <string>', 'is used to generate the secret')
  .action(async (action, options) => {
    try {
      const agent = new SSHAgentClient()
      const key = await agent.getIdentity(options.key)
      if (!key) {
        program.error(`Error: no SSH key found for "${options.key}"`)
      }
      const readable = options.input ? fs.createReadStream(options.input) : process.stdin
      const writable = options.output ? fs.createWriteStream(options.output) : process.stdout
      switch (action) {
        case 'encrypt': {
          await buffer(readable)
            .then(data => agent.encrypt(key, options.seed, data))
            .then(encrypted => writable.write(encrypted))

          break
        }
        case 'decrypt': {
          await text(readable)
            .then(data => agent.decrypt(key, options.seed, data.trim()))
            .then(decrypted => writable.write(decrypted))

          break
        }
        default:
          throw new Error('unknwon action')
      }
    } catch (err) {
      program.error(`Error: ${(err as Error).message}`)
    }
  })

program.parse()
