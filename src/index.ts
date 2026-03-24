#!/usr/bin/env node
import * as fs from 'fs'
import { program } from 'commander'
import { SSHAgentClient } from './lib/ssh_agent_client.js'

program.name('ssh-crypt').description('Encryption through SSH Agent')

program
  .command('encrypt')
  .description('Encrypt a file with your ssh-agent private key')
  .argument('<source>', 'file to encrypt')
  .argument('[destination]', 'output path (default to stdout)')
  .requiredOption('-k, --key <string>', 'select the first matching pubkey in the ssh-agent')
  .requiredOption('-s, --seed <string>', 'is used to generate the secret')
  .action(async (source, destination, options) => {
    const agent = new SSHAgentClient()
    const key = await agent.getIdentity(options.key)
    if (!key) {
      throw new Error(`No SSH key found for "${options.key}"!`)
    }
    const data = fs.readFileSync(source)
    const output = await agent.encrypt(key, options.seed, data)
    if (destination) {
      fs.writeFileSync(destination, output)
    } else {
      process.stdout.write(output)
    }
  })

program
  .command('decrypt')
  .description('Decrypt a file with your ssh-agent private key')
  .argument('<source>', 'file to decrypt')
  .argument('[destination]', 'output path (default to stdout)')
  .requiredOption('-k, --key <string>', 'select the first matching pubkey in the ssh-agent')
  .requiredOption('-s, --seed <string>', 'is used to generate the secret')
  .action(async (source, destination, options) => {
    const agent = new SSHAgentClient()
    const key = await agent.getIdentity(options.key)
    if (!key) {
      throw new Error(`No SSH key found for "${options.key}"!`)
    }
    const data = fs.readFileSync(source, { encoding: 'ascii' })
    const output = await agent.decrypt(key, options.seed, data)
    if (destination) {
      fs.writeFileSync(destination, output)
    } else {
      process.stdout.write(output)
    }
  })

program.parse()
