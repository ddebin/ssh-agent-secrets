import { describe, it } from 'mocha'
import { SSHAgentClient } from '../src/lib/ssh_agent_client.js'
import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'

chai.use(chaiAsPromised)

describe('RSA key mandatory tests', () => {
  it("doesn't give the same signature twice with an ECDSA key", async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa')
    if (!identity) {
      throw new Error()
    }
    const signature1 = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    const signature2 = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    chai.assert.notEqual(signature1, signature2)
  })
  it("doesn't give the same signature twice with an ED25519 key", async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const signature1 = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    const signature2 = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    chai.assert.notEqual(signature1, signature2)
  })
  it('should throw if using ECDSA key for encrypting', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.encrypt(identity, 'not_a_secret', Buffer.from('', 'utf8')))
      .to.be.rejectedWith(
        Error,
        "We can't use ecdsa-sha2-nistp256 key, it always gives different signatures!",
      )
  })
  it('should throw if using ECDSA key for decrypting', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.decrypt(identity, 'not_a_secret', ''))
      .to.be.rejectedWith(
        Error,
        "We can't use ecdsa-sha2-nistp256 key, it always gives different signatures!",
      )
  })
  it('should throw if using ED25519 key for encrypting', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.encrypt(identity, 'not_a_secret', Buffer.from('', 'utf8')))
      .to.be.rejectedWith(Error, "We can't use ssh-ed25519 key, it always gives different signatures!")
  })
  it('should throw if using ED25519 key for decrypting', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.decrypt(identity, 'not_a_secret', ''))
      .to.be.rejectedWith(Error, "We can't use ssh-ed25519 key, it always gives different signatures!")
  })
})
