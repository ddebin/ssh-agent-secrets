import * as chai from 'chai'
import { describe, it } from 'mocha'
import {
  RsaSignatureFlag,
  SSHAgentClient,
  type SSHKey,
  type SSHSignature,
} from '../src/lib/ssh_agent_client.ts'

const DATA = Buffer.from('hello', 'utf8')

describe('SSHAgentClient verify tests', () => {
  it('should verify RSA (ssh-rsa) signature', async () => {
    const agent = new SSHAgentClient({ rsaSignatureFlag: RsaSignatureFlag.DEFAULT })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should verify RSA (rsa-sha2-256) signature', async () => {
    const agent = new SSHAgentClient({ rsaSignatureFlag: RsaSignatureFlag.SSH_AGENT_RSA_SHA2_256 })
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should verify RSA (rsa-sha2-512) signature', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should verify Ed25519 signature', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should verify ECDSA 256 signature', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should verify ECDSA 384 signature', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_384')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should verify ECDSA 521 signature', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_521')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isTrue(SSHAgentClient.verify(signature, identity, DATA))
  })
  it('should return false for wrong data', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ed25519')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    chai.assert.isFalse(SSHAgentClient.verify(signature, identity, Buffer.from('other', 'utf8')))
  })
  it('should return false for corrupted RSA signature', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const signature = await agent.sign(identity, DATA)
    const corruptedRaw = Buffer.alloc(signature.raw.length, 0)
    const corruptedSig: SSHSignature = {
      type: signature.type,
      raw: corruptedRaw,
      signature: corruptedRaw.toString('base64'),
    }
    chai.assert.isFalse(SSHAgentClient.verify(corruptedSig, identity, DATA))
  })
  it('should return false for corrupted RSA signature (wrong DER encoding)', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    const corruptedSig = await agent.sign(identity, DATA)
    corruptedSig.raw[2] = 0x01 // Corrupt the signature bytes to make it invalid
    corruptedSig.raw = Buffer.concat([
      corruptedSig.raw.subarray(0, 8),
      Buffer.alloc(256, 0x01),
      corruptedSig.raw.subarray(8),
    ]) // Set the signature type to an unrecognized value
    chai.assert.isFalse(SSHAgentClient.verify(corruptedSig, identity, DATA))
  })
  it('should throw for unsupported key type', () => {
    const keyTypeName = 'unsupported-type'
    const keyTypeBytes = Buffer.from(keyTypeName, 'ascii')
    const keyTypeLenBuf = Buffer.alloc(4)
    keyTypeLenBuf.writeUInt32BE(keyTypeBytes.length, 0)
    const fakeKey: SSHKey = {
      type: keyTypeName,
      key: '',
      comment: '',
      raw: Buffer.concat([keyTypeLenBuf, keyTypeBytes]),
    }
    const fakeSig: SSHSignature = { type: 'ssh-rsa', signature: '', raw: Buffer.alloc(4) }
    chai
      .expect(() => SSHAgentClient.verify(fakeSig, fakeKey, DATA))
      .to.throw('Unsupported key type: unsupported-type')
  })
  it('should throw for unsupported EC curve', async () => {
    const agent = new SSHAgentClient()
    const fakeKey = await agent.getIdentity('key_ecdsa_256')
    if (!fakeKey) {
      throw new Error()
    }
    fakeKey.raw[34] = 0x00 // Corrupt the curve name to make it unrecognized
    const fakeSig: SSHSignature = { type: 'ssh-rsa', signature: '', raw: Buffer.alloc(4) }
    chai.expect(() => SSHAgentClient.verify(fakeSig, fakeKey, DATA)).to.throw('Unsupported EC curve: nistp25')
  })
  it('should throw for unsupported signature type', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_rsa')
    if (!identity) {
      throw new Error()
    }
    const fakeSig: SSHSignature = { type: 'unsupported-sig', signature: '', raw: Buffer.alloc(4) }
    chai
      .expect(() => SSHAgentClient.verify(fakeSig, identity, DATA))
      .to.throw('Unsupported signature type: unsupported-sig')
  })
  it('should throw for unsupported signature type', async () => {
    const agent = new SSHAgentClient()
    const identity = await agent.getIdentity('key_ecdsa_256')
    if (!identity) {
      throw new Error()
    }
    const fakeSig = await agent.sign(identity, DATA)
    fakeSig.type = 'ecdsa-sha2-nistp25' // Corrupt the signature type to make it unrecognized
    chai
      .expect(() => SSHAgentClient.verify(fakeSig, identity, DATA))
      .to.throw('Unsupported ECDSA signature type: ecdsa-sha2-nistp25')
  })
})
