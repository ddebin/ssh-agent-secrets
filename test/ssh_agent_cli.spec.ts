import * as chai from 'chai'
import { execSync } from 'child_process'

describe('ssh-crypt cli tests', () => {
  it('should show help', () => {
    const output = execSync('npm exec -- tsx src/cli.ts -h', {
      encoding: 'utf8',
      stdio: 'pipe',
    })
    const text =
      'Usage: ssh-crypt [options] <command>\n' +
      '\n' +
      'Encrypt/Decrypt a file with your ssh-agent private key\n' +
      '\n' +
      'Arguments:\n' +
      '  command                       action (choices: "encrypt", "decrypt")\n' +
      '\n' +
      'Options:\n' +
      '  -i, --input <path>            input path (default to stdin)\n' +
      '  --encryptEncoding <encoding>  encrypt output encoding (choices: "hex",\n' +
      '                                "base64")\n' +
      '  -o, --output <path>           output path (default to stdout)\n' +
      '  --decryptEncoding <encoding>  decrypt input encoding (choices: "hex",\n' +
      '                                "base64")\n' +
      '  -k, --key <string>            select the first matching pubkey in the\n' +
      '                                ssh-agent\n' +
      '  -s, --seed <string>           is used to generate the secret\n' +
      '  -h, --help                    display help for command\n'
    chai.assert.strictEqual(output, text)
  })
  it('should encrypt', () => {
    const output = execSync(
      'npm exec -- tsx src/cli.ts -k key_ed25519 -s not_a_secret --encryptEncoding hex encrypt',
      {
        encoding: 'ascii',
        input: 'Lorem ipsum dolor',
        stdio: 'pipe',
      },
    )
    chai.assert.strictEqual(output.length, 96)
  })
  it('should decrypt', () => {
    const data =
      '5f1979820d75926171e7028d5938f64ba5872683334f21b14947df1a4cce1f9ff1bb7c9c91e28e49aa8807b02c18c48c'
    const output = execSync(
      'npm exec -- tsx src/cli.ts -k key_ed25519 -s not_a_secret --decryptEncoding hex decrypt',
      {
        encoding: 'utf8',
        input: data,
        stdio: 'pipe',
      },
    )
    chai.assert.strictEqual(output, 'Lorem ipsum dolor')
  })
  it('should exit with error', () => {
    const data =
      'ecfd6bb57f4891ba7226886e90d2eb848022a495b15ffd91ffe760bca5605f9062c305ee14226d9daf7faa58460c8f50'
    chai
      .expect(() =>
        execSync('npm exec -- tsx src/cli.ts -k key_rsa -s wrong_secret --decryptEncoding hex decrypt', {
          input: data,
          stdio: 'pipe',
        }),
      )
      .to.throw(/bad secret or key, can't decrypt/iu)
  })
})
