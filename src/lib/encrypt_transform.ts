import * as crypto from 'node:crypto'
import { Transform, type TransformCallback, type TransformOptions } from 'node:stream'

export class EncryptTransform extends Transform {
  private iv: Buffer
  private cipher: crypto.Cipher
  private ivSent = false

  constructor(cipher: crypto.Cipher, iv: Buffer, opts?: TransformOptions) {
    super(opts)
    this.iv = iv
    this.cipher = cipher
  }

  override _transform(chunk: any, _encoding: BufferEncoding, callback: TransformCallback) {
    if (!this.ivSent) {
      this.push(this.iv)
      this.ivSent = true
    }
    this.push(this.cipher.update(chunk as Buffer))
    callback()
  }

  override _flush(callback: TransformCallback) {
    this.push(this.cipher.final())
    callback()
  }
}
