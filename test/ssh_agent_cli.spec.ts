import { describe, it } from 'mocha'
import * as chai from 'chai'
import { execSync } from 'child_process'

describe('ssh-crypt cli tests', () => {
  it('should show help', () => {
    const output = execSync(`npm exec -- tsx src/cli.ts -h`, {
      encoding: 'utf8',
    })
    const text =
      'Usage: ssh-crypt [options] <command>\n' +
      '\n' +
      'Encrypt/Decrypt a file with your ssh-agent private key\n' +
      '\n' +
      'Arguments:\n' +
      '  command              action (choices: "encrypt", "decrypt")\n' +
      '\n' +
      'Options:\n' +
      '  -i, --input <path>   input path (default to stdin)\n' +
      '  -o, --output <path>  output path (default to stdout)\n' +
      '  -k, --key <string>   select the first matching pubkey in the ssh-agent\n' +
      '  -s, --seed <string>  is used to generate the secret\n' +
      '  -h, --help           display help for command\n'
    chai.assert.strictEqual(output, text)
  })
  it('should encrypt', () => {
    const output = execSync(
      `echo 'Lorem ipsum dolor' | npm exec -- tsx src/cli.ts -k key_rsa -s not_a_secret encrypt`,
      {
        encoding: 'ascii',
      },
    )
    chai.assert.strictEqual(output.length, 96)
  })
  it('should decrypt', () => {
    const data =
      'ecfd6bb57f4891ba7226886e90d2eb848022a495b15ffd91ffe760bca5605f9062c305ee14226d9daf7faa58460c8f50'
    const output = execSync(
      `echo '${data}' | npm exec -- tsx src/cli.ts -k key_rsa -s not_a_secret decrypt`,
      {
        encoding: 'utf8',
      },
    )
    chai.assert.strictEqual(output, 'Lorem ipsum dolor')
  })
})
