import * as chai from 'chai'
import { describe, it } from 'mocha'
import { RsaSignatureFlag, SSHAgentClient } from '../src/lib/ssh_agent_client.ts'
import chaiAsPromised from 'chai-as-promised'

chai.use(chaiAsPromised)

const DECODED_STRING = 'Lorem ipsum dolor'
const DECODED_STRING_BUFFER = Buffer.from(DECODED_STRING, 'utf8')
const DATA = Buffer.from('hello', 'utf8')
const SEED = 'not_a_secret'

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
    const identities = await agent.getIdentities()
    chai.assert.strictEqual(identities.length, 5)
    const identity = identities.find(id => id.type === 'ssh-rsa')
    if (!identity) {
      throw new Error()
    }
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
  it('should find identity with selector in comment', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    chai.assert.strictEqual(identity.type, 'ecdsa-sha2-nistp256')
    chai.assert.strictEqual(identity.comment, 'key_ecdsa_256')
  })
  it('should find identity with selector in pubkey', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('IwLKBDr4Ve8wxMDTa3N9QnYDt')
    if (!identity) {
      throw new Error()
    }
    chai.assert.strictEqual(identity.type, 'ssh-rsa')
    chai.assert.strictEqual(identity.comment, 'key_rsa')
  })
  it('should sign with key_rsa and default ssh-rsa signature', async () => {
    const agent = new SSHAgentClient({ rsaSignatureFlag: RsaSignatureFlag.DEFAULT })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.strictEqual(signature.type, 'ssh-rsa')
    chai.assert.strictEqual(
      signature.signature,
      '2Ox3c3wtOkmZwINZ0nSi31NP2ysWnERdaLWMcY/CONPcLK3DPBfEolG307yMdmYAsJY5VW/sgw0ye58zOu5daos2xtWxYTHUvY7peDMcJWgQJ5YFBQWGY6ku++tqR31FSlLl9KJMUnXGdE88T1RFbaWOsg8U37IsMd5juxCeakgmcvo4PXOcWlRKBnQKRaxoOl+lQxcBNb3GM2T/kqnKkae5NebaUMOI+v7U95tzNPq0xLrZ0805rNETEcLdMszi6XS8Gbh4iDZNZGV7sA5hh9rB/avhKQHYplJ9YzyLfLEX3S8bZf41xIynt62PXeEUuM5UcYRj1lUC6quGC59Z4P2pBujjvJqj9gmKjwVcwnVo28J9OEugmRnO2QmamR0LIJIhIJmdmRRFqD86vkfyYBz733KRkvA80gXvbvligTI5LZwpUoTX7YWGkpz8fCCrMJ4WRyu9nerp9EGk4afhlAb92wMSqQV3QmXI/uRjHkbs+8rfeZS6i77Xgj4AYkHp',
    )
  })
  it('should sign with key_rsa and SHA2-256 signature', async () => {
    const agent = new SSHAgentClient({ rsaSignatureFlag: RsaSignatureFlag.SSH_AGENT_RSA_SHA2_256 })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.strictEqual(signature.type, 'rsa-sha2-256')
    chai.assert.strictEqual(
      signature.signature,
      'InYgWb2UN3RCyQwKMWNSjljkzmMQ+6D+gwol2PfSrYaXejyKIEFH2ZwzueT0bTD8CEi0l51BZ6Lx5Pdi8JLTgdk3fneJQPayBkzq+QUINNeK8qLICYol36T2Huy2oS1TrqVvlhRZQSvJB8En6jRbsgo9qEoK4GtitiDYqNIdsG3mIEpmP8M+gA/iis6PHAxlT2cHPF8gQu43KXorZ1txvkOnahJ0LAfjB5axz+NvUkEgSbXbK3l4REFm3+TNXq/El9yqnC+5NW09v+m0dctW/YBY0eGpYZoO8pl/oXJ/47M8SOmDZjrmmAwG2zPzTq6Pctv3glVROY8sndcy32VpJs1DEEbk3MGgj2R2HkvCX6PPuhPDpMdcakpfSbOFvRDuYityeijJLA5d6v7EaWBTeH4nX10Dq4O+5CCsdb1dOhzS5gay4aedy2TwU8zpUF0GqzJwxLq7w26nokZLOoLmNFbkGsRXQqVfTPUN5aNNZqMNIdeXcjmvAb7fmcz6Gxdv',
    )
  })
  it('should sign with key_rsa and SHA2-512 signature', async () => {
    const agent = new SSHAgentClient({ rsaSignatureFlag: RsaSignatureFlag.SSH_AGENT_RSA_SHA2_512 })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    chai.assert.strictEqual(signature.type, 'rsa-sha2-512')
    chai.assert.strictEqual(
      signature.signature,
      'PEOu4DK+GXsdgd84PEEAFzQgsSz6kgCGiVgf4d464mBGyXhebFR5HBZ4RPCKDIPAu6zFt7DgAYBDmBio0LdwqgAs561ytLO+pQ1UCS1nmzE8f9n8220vGp18PSIXzDPAwlbAk9tPv940kFWbQOr1GwxmyERWC0XOdMLvueeCx5alThYWOAKbjHLhMSAry9E0I02g44UkoFV0VAgrSff03t9Y31c+n5ogpa2bii02IFg3khycrzaYv+3B+aU9kew7MhFH9awkJLFbFuQbLtOiINwhkZRnTAMbrqZPqeYpKrhHr+D6gjNhYXqNhAfZKBJFUurVAkccmkFWttmAZJwCpoiDD+yrOTYj7s5iQq5M0YlrIv3N+RP7MyN9GhvWwlD/Ti5Mnc7EckAIBIrFAja8hdJqmNbeVKD2o5tqJopvz7vvGpOiUHAZyL9Gbd74W3yjX971rZKSHsKtC7ngi3GqUK64QJ/sLjutQXnsxCWvEPaltnsT8dlyjdi2iizP1Prn',
    )
  })
  it('should sign with ed25519', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    chai.assert.strictEqual(signature.type, 'ssh-ed25519')
    chai.assert.strictEqual(
      signature.signature,
      'Uolma4H0fzvBSu1G/6pUYZthmFH/NjXRjP4Zx80SloXMIlTFsF/++HqOi4ooEhLoTh/ZlhAlyEONjVqqcAnWAQ==',
    )
  })
  it('can sign with ecdsa', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, Buffer.from('hello', 'utf8'))
    chai.assert.strictEqual(signature.type, 'ecdsa-sha2-nistp256')
    // Can't assert signature value as it is not deterministic
  })
  it('should throw if wrong secret', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const data =
      'ecfd6bb57f4891ba7226886e90d2eb848022a495b15ffd91ffe760bca5605f9062c305ee14226d9daf7faa58460c8f50'
    return chai
      .expect(agent.decrypt(identity, 'wrong_secret', data))
      .to.be.rejectedWith(Error, /bad decrypt/iu)
  })
  it('should throw if corrupted encrypted data', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const data =
      'ecfd6bb57f4891ba7226886e90d2eb848022a495b15ffd91ffe760bca5605f9062c305ee14226d9daf7faa58460c8f'
    return chai
      .expect(agent.decrypt(identity, SEED, data))
      .to.be.rejectedWith(Error, 'error:1C80006B:Provider routines::wrong final block length')
  })
  it('should throw if cipher algorithm is unknown', async () => {
    const agent = new SSHAgentClient({ cipherAlgo: 'xxx' })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.encrypt(identity, SEED, DECODED_STRING_BUFFER))
      .to.be.rejectedWith(Error, 'Unknown symmetric cipher algo')
  })
  it('should throw if digest length is less than cipher key length', async () => {
    const agent = new SSHAgentClient({ cipherAlgo: 'aes-192-cbc', digestAlgo: 'sha1' })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.encrypt(identity, SEED, DECODED_STRING_BUFFER))
      .to.be.rejectedWith(Error, "Digest length doesn't match cipher key length")
  })
  it('should throw if hash algorithm is unknown', async () => {
    const agent = new SSHAgentClient({ digestAlgo: 'xxx' })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    return chai
      .expect(agent.encrypt(identity, SEED, DECODED_STRING_BUFFER))
      .to.be.rejectedWith(Error, 'Unknown digest algo')
  })
})

describe('SSHAgentClient cipher combination tests', () => {
  it('should encrypt', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const encrypted = await agent.encrypt(identity, SEED, DECODED_STRING_BUFFER)
    chai.assert.strictEqual(encrypted.length, 96)
  })
  it('should decrypt', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const decrypted = await agent.decrypt(
      identity,
      SEED,
      '5af153e6fbf83b40cf98ed8bf5710321aa3234b2121cc3d8c47ef6854007f35ece319b056ddba7791b1db776b26a7ea7',
    )
    chai.assert.strictEqual(decrypted.toString('utf8'), DECODED_STRING)
  })
  it('should encrypt and decrypt with aes128/shake128', async () => {
    const agent = new SSHAgentClient({ cipherAlgo: 'aes-128-cbc', digestAlgo: 'shake128' })
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const encrypted = await agent.encrypt(identity, SEED, DECODED_STRING_BUFFER)
    chai.assert.strictEqual(encrypted.length, 96)
    const decrypted = await agent.decrypt(
      identity,
      SEED,
      '9a9bdd5451fd1ed8220f4ce23a17aa0981d69521cadd73ff219fd85aa01bc8a3a44cbe95502854a5b37296e93a91db91',
    )
    chai.assert.strictEqual(decrypted.toString('utf8'), DECODED_STRING)
  })
  it('should encrypt and decrypt with non matching aes192/sha512', async () => {
    const agent = new SSHAgentClient({ cipherAlgo: 'aes-192-cbc', digestAlgo: 'sha512' })
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const encrypted = await agent.encrypt(identity, SEED, DECODED_STRING_BUFFER)
    chai.assert.strictEqual(encrypted.length, 96)
    const decrypted = await agent.decrypt(
      identity,
      SEED,
      '1e69398e2ad6ab5e1f748d538fafe6e54e9824b0646af6666437c556398a7495b48f76db5df52d52f9adde0a232465ab',
    )
    chai.assert.strictEqual(decrypted.toString('utf8'), DECODED_STRING)
  })
})

describe('SSHAgentClient encodings tests', () => {
  it('should encrypt to base64', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const encrypted = await agent.encrypt(identity, SEED, DECODED_STRING_BUFFER, 'base64')
    chai.assert.strictEqual(encrypted.length, 64)
  })
  it('should decrypt from base64', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const decrypted = await agent.decrypt(
      identity,
      SEED,
      'QMf1r1/ZONTJImZyY1qO+ibDTqLCZNwD2dMs/tpfVpfLKovb7flyiU1Au/01xffv',
      'base64',
    )
    chai.assert.strictEqual(decrypted.toString('utf8'), DECODED_STRING)
  })
})
