import * as crypto from 'crypto'
import { type SSHKey, type SSHSignature } from './ssh_agent_client.ts'

/** Read a length-prefixed string (uint32 BE length + bytes) from a buffer. */
const readString = (buffer: Buffer, offset: number): Buffer => {
  const len = buffer.readUInt32BE(offset)
  return buffer.subarray(offset + 4, offset + 4 + len)
}

/** Write a length-prefixed string into `target` at `offset`, return next offset. */
const writeString = (target: Buffer, src: Buffer, offset: number): number => {
  target.writeUInt32BE(src.length, offset)
  src.copy(target, offset + 4)
  return offset + 4 + src.length
}

/**
 * Write the 5-byte SSH agent frame header (4-byte length + 1-byte tag)
 * into `request` and return the next write offset (5).
 * The length field is the total buffer length minus the 4-byte length field itself.
 */
const writeHeader = (request: Buffer, tag: number): number => {
  request.writeUInt32BE(request.length - 4, 0)
  request.writeUInt8(tag, 4)
  return 5
}

const sshEcCurveParam = (curve: string): { crv: string; coordLen: number } => {
  if (curve === 'nistp256') return { crv: 'P-256', coordLen: 32 }
  if (curve === 'nistp384') return { crv: 'P-384', coordLen: 48 }
  if (curve === 'nistp521') return { crv: 'P-521', coordLen: 66 }
  throw new Error(`Unsupported EC curve: ${curve}`)
}

const ecdsaHashAlgo = (sigType: string): string => {
  if (sigType === 'ecdsa-sha2-nistp256') return 'SHA256'
  if (sigType === 'ecdsa-sha2-nistp384') return 'SHA384'
  if (sigType === 'ecdsa-sha2-nistp521') return 'SHA512'
  throw new Error(`Unsupported ECDSA signature type: ${sigType}`)
}

/** Convert an SSH public key blob to a Node.js `crypto.KeyObject`. */
const parseSSHPublicKey = (key: SSHKey): crypto.KeyObject => {
  const blob = key.raw
  const type = readString(blob, 0)
  const keyType = type.toString('ascii')

  if (keyType === 'ssh-rsa') {
    const rsaOffset = 4 + type.length
    const exponent = readString(blob, rsaOffset)
    const modulus = readString(blob, rsaOffset + 4 + exponent.length)
    return crypto.createPublicKey({
      // eslint-disable-next-line id-length
      key: { kty: 'RSA', n: modulus.toString('base64url'), e: exponent.toString('base64url') },
      format: 'jwk',
    })
  }

  if (keyType === 'ssh-ed25519') {
    const pubKeyBytes = readString(blob, 4 + type.length)
    // SPKI DER encoding for Ed25519 (OID 1.3.101.112)
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex')
    return crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, pubKeyBytes]),
      format: 'der',
      type: 'spki',
    })
  }

  if (keyType.startsWith('ecdsa-sha2-')) {
    const ecOffset = 4 + type.length
    const curveName = readString(blob, ecOffset)
    const point = readString(blob, ecOffset + 4 + curveName.length)
    const { crv, coordLen } = sshEcCurveParam(curveName.toString('ascii'))
    // Uncompressed EC point: 0x04 || x || y
    const pointX = point.subarray(1, 1 + coordLen)
    const pointY = point.subarray(1 + coordLen)
    return crypto.createPublicKey({
      // eslint-disable-next-line id-length
      key: { kty: 'EC', crv, x: pointX.toString('base64url'), y: pointY.toString('base64url') },
      format: 'jwk',
    })
  }

  throw new Error(`Unsupported key type: ${keyType}`)
}

const encodeDerLength = (len: number): Buffer => {
  if (len < 128) return Buffer.from([len])
  if (len < 256) return Buffer.from([0x81, len])
  return Buffer.from([0x82, Math.floor(len / 256), len % 256])
}

const encodeDerInt = (bytes: Buffer): Buffer => {
  // Strip leading zeros, keeping at least one byte
  let start = 0
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1
  const trimmed = bytes.subarray(start)
  // Prepend 0x00 if high bit is set to keep the DER INTEGER positive
  const [firstByte] = trimmed
  const content = firstByte >= 0x80 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed
  return Buffer.concat([Buffer.from([0x02]), encodeDerLength(content.length), content])
}

/** Map an SSH signature to the hash algorithm and signature bytes expected by `crypto.verify`. */
const parseSSHSignature = (signature: SSHSignature): { algorithm: string | null; raw: Buffer } => {
  const { type, raw } = signature

  if (type === 'rsa-sha2-256') return { algorithm: 'SHA256', raw }
  if (type === 'rsa-sha2-512') return { algorithm: 'SHA512', raw }
  if (type === 'ssh-rsa') return { algorithm: 'SHA1', raw }
  if (type === 'ssh-ed25519') return { algorithm: null, raw }

  if (type.startsWith('ecdsa-sha2-')) {
    // SSH ECDSA signature: mpint(r) || mpint(s) → DER ASN.1 SEQUENCE { INTEGER r, INTEGER s }
    const sigR = readString(raw, 0)
    const sigS = readString(raw, 4 + sigR.length)
    const rDer = encodeDerInt(sigR)
    const sDer = encodeDerInt(sigS)
    const seqContent = Buffer.concat([rDer, sDer])
    const rawECDSA = Buffer.concat([Buffer.from([0x30]), encodeDerLength(seqContent.length), seqContent])
    return { algorithm: ecdsaHashAlgo(type), raw: rawECDSA }
  }

  throw new Error(`Unsupported signature type: ${type}`)
}

export { readString, writeString, writeHeader, parseSSHPublicKey, parseSSHSignature }
