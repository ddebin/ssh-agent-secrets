import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { Readable } from 'stream'
import { SSHAgentClient } from '../src/lib/ssh_agent_client.ts'
import { text } from 'stream/consumers'

chai.use(chaiAsPromised)

const DECODED_STRING = 'Lorem ipsum dolor'
const DECODED_STRING_BUFFER = Buffer.from(DECODED_STRING, 'utf8')
const SEED = 'not_a_secret'

describe('SSHAgentClient streams tests', () => {
  it('should encrypt', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const transform = await agent.getEncryptTransform(identity, SEED, 'hex')
    const stream = Readable.from(DECODED_STRING_BUFFER)
    const encrypted = await text(stream.pipe(transform))
    chai.assert.strictEqual(encrypted.length, 96)
  })
  it('should decrypt', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const transform = await agent.getDecryptTransform(identity, SEED, 'hex')
    const stream = Readable.from(
      '2e306f1403b72eb17fe7187545dbd863be234ad1128ac3f34d60d102ced7bc43a7c4506d341463cff257b4d007b39143',
    )
    const decrypted = await text(stream.pipe(transform))
    chai.assert.strictEqual(decrypted, DECODED_STRING)
  })
})

describe('SSHAgentClient streams encodings tests', () => {
  it('should encrypt to base64', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const transform = await agent.getEncryptTransform(identity, SEED, 'base64')
    const stream = Readable.from(DECODED_STRING_BUFFER)
    const encrypted = await text(stream.pipe(transform))
    chai.assert.strictEqual(encrypted.length, 64)
  })
  it('should decrypt from base64', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const transform = await agent.getDecryptTransform(identity, SEED, 'base64')
    const stream = Readable.from('5e0UbJX4+Rad+byLPnRNho3Qvjbeeqcwmg7yrXinHrTZ0788uuyvTl9jjbcpErF6')
    const decrypted = await text(stream.pipe(transform))
    chai.assert.strictEqual(decrypted, DECODED_STRING)
  })
})
