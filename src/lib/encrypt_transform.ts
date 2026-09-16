import { Transform, type TransformCallback, type TransformOptions } from 'node:stream'
import { type Cipher } from 'node:crypto'

export class EncryptTransform extends Transform {
  private iv: Buffer
  private cipher: Cipher
  private ivSent = false

  constructor(cipher: Cipher, iv: Buffer, opts?: TransformOptions) {
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
