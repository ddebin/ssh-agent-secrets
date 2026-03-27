import * as crypto from 'node:crypto'
import { Transform, type TransformCallback, type TransformOptions } from 'node:stream'

export class DecryptTransform extends Transform {
  private decipher?: crypto.Decipher
  private algo: string
  private cipherKey: crypto.KeyObject
  private cipherIvLength: number
  private inputEncoding?: BufferEncoding

  constructor(
    algo: string,
    cipherKey: crypto.KeyObject,
    cipherIvLength: number,
    inputEncoding?: BufferEncoding,
    opts?: TransformOptions,
  ) {
    super(opts)
    this.algo = algo
    this.cipherKey = cipherKey
    this.cipherIvLength = cipherIvLength
    this.inputEncoding = inputEncoding
  }

  override _transform(chunk: any, _encoding: BufferEncoding, callback: TransformCallback) {
    let data = chunk as Buffer
    if (this.inputEncoding && this.inputEncoding !== 'binary') {
      data = Buffer.from(data.toString().trim(), this.inputEncoding)
    }
    if (!this.decipher) {
      // Unpackage the combined iv + encrypted message.
      // Since we are using a fixed size IV, we can hard code the slice length.
      const iv = data.subarray(0, this.cipherIvLength)
      this.decipher = crypto.createDecipheriv(this.algo, this.cipherKey, iv)
      data = data.subarray(this.cipherIvLength)
    }
    this.push(this.decipher.update(data))
    callback()
  }

  override _flush(callback: TransformCallback) {
    this.push(this.decipher?.final())
    callback()
  }
}
