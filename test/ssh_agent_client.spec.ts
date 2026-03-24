import { describe, it } from 'mocha'
import { SSHAgentClient } from '../src/lib/ssh_agent_client.js'
import * as chai from 'chai'

describe('SSHAgentClient tests', () => {
  it('should throw for non existent socket', () => {
    chai
      .expect(
        () =>
          new SSHAgentClient({
            sockFile: 'nil.sock',
          }),
      )
      .to.throw('Socket nil.sock not found')
  })
  it('should throw for unset socket info', () => {
    const backup = process.env.SSH_AUTH_SOCK
    delete process.env.SSH_AUTH_SOCK
    chai.expect(() => new SSHAgentClient()).to.throw('Socket ? not found')
    if (backup) {
      process.env.SSH_AUTH_SOCK = backup
    }
  })
  it('should find identites', async () => {
    const agent = new SSHAgentClient()
    const identities = await agent.requestIdentities()
    chai.assert.strictEqual(identities.length, 3)
    const [identity] = identities
    chai.assert.strictEqual(identity.type, 'ssh-rsa')
    chai.assert.strictEqual(
      identity.key,
      'AAAAB3NzaC1yc2EAAAADAQABAAABgQDduXTiGIwLKBDr4Ve8wxMDTa3N9QnYDtuus4FyWZ7/ONzgBZiykCZjrQW5EX0Z4XTmAwaW+gMw59UAoZVYrhaojp4wE7KCpldsggzgAQQ7YqW/jqE6svtnZOFq0WF20GSYpoRS7GYuy17ixQhvLXJmucwqfXnHlDF+PC12u+vFLYNJV04KXL2pWvIo3rprHC58hgYXt2O7HZy2C0JFG9ZF7GIRu4zJx8Bzrk6AW6Fvae1oQWpYBvV6D9f0jVuhh0H6YHAU5zswh9Fj5Rsk3n7MNMKmOyiOcoKCysqMno/QTRdj0isCPikFzf8tOeINlElxZUxqbvfQWypPB/RjZvpkjG2RooPwgzor5PtERUe02VG/J5a7RtZCTm8gMD/SJdIjraGmRUtxHIvuYRjCDTGoI/kIJB7Egt7SCtAIVAvHmDaryIgIh4yQwheiLYSH/NK5Re35XiqbwoE4/MFfj4IF8cSOn3qTyCGBxJnSQoLXqy7Ss7cE//yIcde3SZqcTwU=',
    )
    chai.assert.strictEqual(identity.comment, 'key_rsa')
  })
  it('should not find identity with selector', async () => {
    const agent = new SSHAgentClient()
    const unknownKey = await agent.getIdentity('unknown_key')
    chai.assert.isUndefined(unknownKey)
  })
  it('should find identity with selector', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa')
    if (!identity) {
      throw new Error()
    }
    chai.assert.strictEqual(identity.type, 'ecdsa-sha2-nistp256')
    chai.assert.strictEqual(identity.comment, 'key_ecdsa')
  })
  it('should sign', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    chai.assert.strictEqual(signature.type, 'ssh-rsa')
    chai.assert.strictEqual(
      signature.signature,
      '2Ox3c3wtOkmZwINZ0nSi31NP2ysWnERdaLWMcY/CONPcLK3DPBfEolG307yMdmYAsJY5VW/sgw0ye58zOu5daos2xtWxYTHUvY7peDMcJWgQJ5YFBQWGY6ku++tqR31FSlLl9KJMUnXGdE88T1RFbaWOsg8U37IsMd5juxCeakgmcvo4PXOcWlRKBnQKRaxoOl+lQxcBNb3GM2T/kqnKkae5NebaUMOI+v7U95tzNPq0xLrZ0805rNETEcLdMszi6XS8Gbh4iDZNZGV7sA5hh9rB/avhKQHYplJ9YzyLfLEX3S8bZf41xIynt62PXeEUuM5UcYRj1lUC6quGC59Z4P2pBujjvJqj9gmKjwVcwnVo28J9OEugmRnO2QmamR0LIJIhIJmdmRRFqD86vkfyYBz733KRkvA80gXvbvligTI5LZwpUoTX7YWGkpz8fCCrMJ4WRyu9nerp9EGk4afhlAb92wMSqQV3QmXI/uRjHkbs+8rfeZS6i77Xgj4AYkHp',
    )
  })
  it('should encrypt', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const encrypted = await agent.encrypt(identity, 'not_a_secret', Buffer.from('Lorem ipsum dolor', 'utf8'))
    chai.assert.strictEqual(encrypted.length, 96)
  })
  it('should decrypt', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const data =
      'ecfd6bb57f4891ba7226886e90d2eb848022a495b15ffd91ffe760bca5605f9062c305ee14226d9daf7faa58460c8f50'
    const decrypted = await agent.decrypt(identity, 'not_a_secret', data)
    chai.assert.strictEqual(decrypted.toString('utf8'), 'Lorem ipsum dolor')
  })
})
