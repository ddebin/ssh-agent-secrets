import * as chai from 'chai'
import { describe, it } from 'mocha'
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
    const identity = await agent.getIdentity('key_rsa')
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
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const transform = await agent.getDecryptTransform(identity, SEED, 'hex')
    const stream = Readable.from(
      'ecfd6bb57f4891ba7226886e90d2eb848022a495b15ffd91ffe760bca5605f9062c305ee14226d9daf7faa58460c8f50',
    )
    const decrypted = await text(stream.pipe(transform))
    chai.assert.strictEqual(decrypted, DECODED_STRING)
  })
})

describe('SSHAgentClient streams encodings tests', () => {
  it('should encrypt to base64', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
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
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const transform = await agent.getDecryptTransform(identity, SEED, 'base64')
    const stream = Readable.from('8epe+B3bWcSGTPpyW2MRqHeAKjTj2NVnR4q1YNVB5LfXw9JE02wsb3RqZBTFbMXc')
    const decrypted = await text(stream.pipe(transform))
    chai.assert.strictEqual(decrypted, DECODED_STRING)
  })
})
