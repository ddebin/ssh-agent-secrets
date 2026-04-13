import * as chai from 'chai'
import { describe, it } from 'mocha'
import chaiAsPromised from 'chai-as-promised'
import { SSHAgentClient } from '../src/lib/ssh_agent_client.ts'

chai.use(chaiAsPromised)

describe('SSH key type tests', () => {
  it('does give the same signature twice with RSA key', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const buffer = Buffer.from('not_a_secret', 'utf8')
    const signature1 = await agent.sign(identity, buffer)
    const signature2 = await agent.sign(identity, buffer)
    chai.assert.equal(signature1.signature, signature2.signature)
  })
  it('does give the same signature twice with ED25519 key', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const buffer = Buffer.from('not_a_secret', 'utf8')
    const signature1 = await agent.sign(identity, buffer)
    const signature2 = await agent.sign(identity, buffer)
    chai.assert.equal(signature1.signature, signature2.signature)
  })
  it("doesn't give the same signature twice with an ECDSA key", async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    const buffer = Buffer.from('not_a_secret', 'utf8')
    const signature1 = await agent.sign(identity, buffer)
    const signature2 = await agent.sign(identity, buffer)
    chai.assert.notEqual(signature1.signature, signature2.signature)
  })
  it('should throw if using ECDSA key for encrypting', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.encrypt(identity, 'not_a_secret', Buffer.from('', 'utf8')))
      .to.be.rejectedWith(
        Error,
        'ecdsa-sha2-nistp256 key is forbidden, it always gives different signatures!',
      )
  })
  it('should throw if using ECDSA key for decrypting', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.decrypt(identity, 'not_a_secret', ''))
      .to.be.rejectedWith(
        Error,
        'ecdsa-sha2-nistp256 key is forbidden, it always gives different signatures!',
      )
  })
})
