#!/usr/bin/env node
/* eslint-disable max-params */
import * as fs from 'fs'
import { Argument, program } from 'commander'
import { SSHAgentClient } from './lib/ssh_agent_client.js'

program
  .name('ssh-crypt')
  .description('Encrypt/Decrypt a file with your ssh-agent private key')
  .addArgument(new Argument('<command>').choices(['encrypt', 'decrypt']))
  .argument('<source>', 'file to encrypt')
  .argument('[destination]', 'output path (default to stdout)')
  .requiredOption('-k, --key <string>', 'select the first matching pubkey in the ssh-agent')
  .requiredOption('-s, --seed <string>', 'is used to generate the secret')
  .action(async (action, source, destination, options) => {
    const agent = new SSHAgentClient()
    const key = await agent.getIdentity(options.key)
    if (!key) {
      throw new Error(`No SSH key found for "${options.key}"!`)
    }
    const output = async () => {
      switch (action) {
        case 'encrypt': {
          const data = fs.readFileSync(source)
          return agent.encrypt(key, options.seed, data).then(encrypted => Buffer.from(encrypted, 'ascii'))
        }
        case 'decrypt': {
          const data = fs.readFileSync(source, { encoding: 'ascii' })
          return agent.decrypt(key, options.seed, data)
        }
        default:
          throw new Error('Unknwon action!')
      }
    }
    if (destination) {
      fs.writeFileSync(destination, await output())
    } else {
      process.stdout.write(await output())
    }
  })

program.parse()
