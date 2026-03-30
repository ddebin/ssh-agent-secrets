import * as crypto from 'node:crypto'
import { createConnection } from 'node:net'
import { DecryptTransform } from './decrypt_transform.ts'
import { EncryptTransform } from './encrypt_transform.ts'
import { existsSync } from 'node:fs'

const Protocol = {
  SSH_AGENTC_REQUEST_RSA_IDENTITIES: 11,
  SSH_AGENT_IDENTITIES_ANSWER: 12,
  SSH2_AGENTC_SIGN_REQUEST: 13,
  SSH2_AGENT_SIGN_RESPONSE: 14,
  SSH_AGENT_FAILURE: 5,
  SSH_AGENT_SUCCESS: 6,
} as const

type Protocol = (typeof Protocol)[keyof typeof Protocol]

export interface SSHKey {
  /** E.g. "ssh-rsa" */
  type: string
  /** Base64-encoded public key blob */
  key: string
  /** Human-readable comment, typically the key file path */
  comment: string
  /** Raw binary key blob — required by sign() */
  raw: Buffer
}

export interface SSHSignature {
  /** E.g. "ssh-rsa" */
  type: string
  /** Base64-encoded signature */
  signature: string
  /** Raw binary signature */
  raw: Buffer
}

export interface SSHAgentClientOptions {
  timeout?: number
  sockFile?: string
  cipherAlgo?: string
  digestAlgo?: string
}

/** Read a length-prefixed string (uint32 BE length + bytes) from a buffer. */
const readString = function readString(buffer: Buffer, offset: number): Buffer {
  const len = buffer.readUInt32BE(offset)
  return buffer.subarray(offset + 4, offset + 4 + len)
}

/** Write a length-prefixed string into `target` at `offset`, return next offset. */
const writeString = function writeString(target: Buffer, src: Buffer, offset: number): number {
  target.writeUInt32BE(src.length, offset)
  src.copy(target, offset + 4)
  return offset + 4 + src.length
}

/**
 * Write the 5-byte SSH agent frame header (4-byte length + 1-byte tag)
 * into `request` and return the next write offset (5).
 * The length field is the total buffer length minus the 4-byte length field itself.
 */
const writeHeader = function writeHeader(request: Buffer, tag: number): number {
  request.writeUInt32BE(request.length - 4, 0)
  request.writeUInt8(tag, 4)
  return 5
}

export class SSHAgentClient {
  private readonly timeout: number
  private readonly sockFile: string
  private readonly cipherAlgo: string
  private readonly digestAlgo: string

  /**
   * @param options - Optional configuration.
   * @throws {Error} if SSH_AUTH_SOCK is not set or socket not found.
   */
  constructor(options: SSHAgentClientOptions = {}) {
    /** Socket operation timeout in milliseconds (default: 10000) */
    this.timeout = options.timeout ?? 10000

    /** Digest and cipher key length must match */
    this.cipherAlgo = options.cipherAlgo ?? 'aes-256-cbc'
    this.digestAlgo = options.digestAlgo ?? 'sha256'

    const sockFile = options.sockFile ?? process.env.SSH_AUTH_SOCK
    if (!sockFile || !existsSync(sockFile)) {
      throw new Error(`Socket ${sockFile ?? '?'} not found`)
    }
    this.sockFile = sockFile
  }

  /**
   * Find an SSH key
   *
   * @param selector - (partially) matching an SSH key comment or pubkey
   */
  async getIdentity(selector: string): Promise<SSHKey | undefined> {
    const identities = await this.getIdentities()
    return identities.find(identity => identity.comment.includes(selector) || identity.key.includes(selector))
  }

  /**
   * List all SSH identities available from the agent.
   *
   * Resolves with an array of key objects:
   * ```ts
   * { type: "ssh-rsa", ssh_key: "<base64>", comment: "~/.ssh/id_rsa", raw: Buffer }
   * ```
   */
  getIdentities(): Promise<SSHKey[]> {
    const buildRequest = (): Buffer => {
      const req = Buffer.allocUnsafe(5) // 4-byte length + 1-byte tag
      writeHeader(req, Protocol.SSH_AGENTC_REQUEST_RSA_IDENTITIES)
      return req
    }

    const parseResponse = (payload: Buffer): SSHKey[] => {
      const numKeys = payload.readUInt32BE(0)
      let offset = 4
      const keys: SSHKey[] = []

      for (let idx = 0; idx < numKeys; idx += 1) {
        const keyBlob = readString(payload, offset)
        offset += 4 + keyBlob.length

        const comment = readString(payload, offset)
        offset += 4 + comment.length

        const type = readString(keyBlob, 0)

        keys.push({
          type: type.toString('ascii'),
          key: keyBlob.toString('base64'),
          comment: comment.toString('utf8'),
          raw: keyBlob,
        })
      }

      return keys
    }

    return this.request(buildRequest, parseResponse, Protocol.SSH_AGENT_IDENTITIES_ANSWER)
  }

  /**
   * Ask the SSH agent to sign `data` with the given `key`.
   *
   * `key` must come from {@link getIdentities} or {@link getIdentity}.
   *
   * Resolves with:
   * ```ts
   * { type: "ssh-rsa", signature: "<base64>", raw: Buffer }
   * ```
   */
  sign(key: SSHKey, data: Buffer): Promise<SSHSignature> {
    const buildRequest = (): Buffer => {
      // Frame: length(4) + tag(1) + key_blob(4+n) + data(4+m) + flags(4)
      const req = Buffer.allocUnsafe(4 + 1 + 4 + key.raw.length + 4 + data.length + 4)
      let offset = writeHeader(req, Protocol.SSH2_AGENTC_SIGN_REQUEST)
      offset = writeString(req, key.raw, offset)
      offset = writeString(req, data, offset)
      req.writeUInt32BE(0, offset) // Flags = 0
      return req
    }

    const parseResponse = (payload: Buffer): SSHSignature => {
      const blob = readString(payload, 0)
      const type = readString(blob, 0)
      const signature = readString(blob, 4 + type.length)

      return {
        type: type.toString('ascii'),
        signature: signature.toString('base64'),
        raw: signature,
      }
    }

    return this.request(buildRequest, parseResponse, Protocol.SSH2_AGENT_SIGN_RESPONSE)
  }

  /**
   * Encrypt data with given `SSHKey` and `seed` string, using SSH signature as the encryption key.
   *
   * Resolves with a string containing the IV and encrypted data, encoded in `outputEncoding` (default: "hex").
   * The IV is needed for decryption and is included in the output as a prefix to the encrypted data.
   */
  async encrypt(
    key: SSHKey,
    seed: string,
    data: NodeJS.ArrayBufferView,
    outputEncoding: BufferEncoding = 'hex',
  ): Promise<string> {
    return this.getCipherIV(key, seed).then(({ cipher, iv }) =>
      // Package the IV and encrypted data together so it can be stored in a single column in the database.
      Buffer.concat([iv, cipher.update(data), cipher.final()]).toString(outputEncoding),
    )
  }

  /**
   * Get a Transform stream that encrypts data with given `SSHKey` and `seed` string, using SSH signature as
   * the encryption key.
   *
   * The Transform stream outputs plain binary or a string encoded in `outputEncoding`.
   * The IV is needed for decryption and is included in the output as a prefix to the encrypted data.
   */
  async getEncryptTransform(
    key: SSHKey,
    seed: string,
    outputEncoding?: BufferEncoding,
  ): Promise<EncryptTransform> {
    return this.getCipherIV(key, seed).then(({ cipher, iv }) => {
      const transform = new EncryptTransform(cipher, iv)
      if (outputEncoding) {
        transform.setEncoding(outputEncoding)
      }
      return transform
    })
  }

  /**
   * Decrypt data with given `SSHKey` and `seed` string, using SSH signature as the decryption key.
   *
   * Resolves with a Buffer containing the decrypted data.
   * The IV is needed for decryption and should be included in the input as a prefix to the encrypted data.
   */
  async decrypt(
    key: SSHKey,
    seed: string,
    data: string,
    inputEncoding: BufferEncoding = 'hex',
  ): Promise<Buffer> {
    return this.getCipherKey(key, seed).then(({ cipherKey, ivLength }) => {
      // Unpackage the combined iv + encrypted message.
      // Since we are using a fixed size IV, we can hard code the slice length.
      const buffer = Buffer.from(data, inputEncoding)
      const iv = buffer.subarray(0, ivLength)
      const encrypted = buffer.subarray(ivLength)
      const decipher = crypto.createDecipheriv(this.cipherAlgo, cipherKey, iv)
      return Buffer.concat([decipher.update(encrypted), decipher.final()])
    })
  }

  /**
   * Get a Transform stream that decrypts data with given `SSHKey` and `seed` string, using SSH signature as
   * the decryption key.
   *
   * The Transform stream expects encrypted data (as plain binary or a string encoded in `inputEncoding`) and
   * outputs a Buffer containing the decrypted data.
   * The IV is needed for decryption and should be included in the input as a prefix to the encrypted data.
   */
  async getDecryptTransform(
    key: SSHKey,
    seed: string,
    inputEncoding?: BufferEncoding,
  ): Promise<DecryptTransform> {
    return this.getCipherKey(key, seed).then(
      ({ cipherKey, ivLength }) => new DecryptTransform(this.cipherAlgo, cipherKey, ivLength, inputEncoding),
    )
  }

  private async getCipherIV(key: SSHKey, seed: string): Promise<{ cipher: crypto.Cipher; iv: Buffer }> {
    return this.getCipherKey(key, seed).then(({ cipherKey, ivLength }) => {
      const iv = crypto.randomBytes(ivLength)
      const cipher = crypto.createCipheriv(this.cipherAlgo, cipherKey, iv)
      return { cipher, iv }
    })
  }

  private async getCipherKey(
    key: SSHKey,
    seed: string,
  ): Promise<{ cipherKey: crypto.KeyObject; ivLength: number }> {
    if (/ecdsa/iu.test(key.type)) {
      throw new Error(`${key.type} key is forbidden, it always gives different signatures!`)
    }
    // Use SSH signature as decryption key
    return this.sign(key, Buffer.from(seed, 'utf8')).then(signature => {
      const cipherInfo = crypto.getCipherInfo(this.cipherAlgo)
      if (!cipherInfo?.ivLength) {
        throw new Error('Unknown symmetric cipher algo')
      }
      if (!crypto.getHashes().includes(this.digestAlgo)) {
        throw new Error('Unknown digest algo')
      }
      const digest = crypto.createHash(this.digestAlgo).update(signature.raw).digest()
      if (digest.length < cipherInfo.keyLength) {
        throw new Error("Digest length doesn't match cipher key length")
      }
      return {
        cipherKey: crypto.createSecretKey(digest.subarray(0, cipherInfo.keyLength)),
        ivLength: cipherInfo.ivLength,
      }
    })
  }

  /**
   * Open a Unix socket to the agent, write a request, and read exactly one
   * response frame. Validates the frame length and message type before handing
   * the payload to `parseResponse`.
   */
  private request<T>(
    buildRequest: () => Buffer,
    parseResponse: (payload: Buffer) => T,
    expectedType: number,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const socket = createConnection(this.sockFile)
      let receivedData = false
      let timedOut = false

      socket.on('connect', () => {
        socket.write(buildRequest())
      })

      socket.on('data', (data: Buffer) => {
        receivedData = true
        socket.end()

        const frameLength = data.readUInt32BE(0)
        if (frameLength !== data.length - 4) {
          reject(
            new Error(`InvalidProtocolError: Expected frame length ${frameLength}, got ${data.length - 4}`),
          )
          return
        }

        const messageType = data.readUInt8(4)
        if (messageType !== expectedType) {
          reject(new Error(`InvalidProtocolError: Expected message type ${expectedType}, got ${messageType}`))
          return
        }

        try {
          resolve(parseResponse(data.subarray(5)))
        } catch (err) {
          reject(err as Error)
        }
      })

      socket.on('close', (hadError: boolean) => {
        if (!hadError && !receivedData && !timedOut) {
          reject(new Error('InvalidProtocolError: No response from SSH agent'))
        }
      })

      socket.on('error', reject)

      socket.setTimeout(this.timeout, () => {
        timedOut = true
        socket.destroy()
        reject(new Error(`Request timed out after ${this.timeout} ms`))
      })
    })
  }
}
