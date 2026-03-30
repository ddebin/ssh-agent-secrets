import * as crypto from 'node:crypto'
import { Transform, type TransformCallback, type TransformOptions } from 'node:stream'

export class DecryptTransform extends Transform {
  private decipher?: crypto.Decipher
  private algo: string
  private cipherKey: crypto.KeyObject
  private ivLength: number
  private inputEncoding?: BufferEncoding

  constructor(
    algo: string,
    cipherKey: crypto.KeyObject,
    ivLength: number,
    inputEncoding?: BufferEncoding,
    opts?: TransformOptions,
  ) {
    super(opts)
    this.algo = algo
    this.cipherKey = cipherKey
    this.ivLength = ivLength
    this.inputEncoding = inputEncoding
  }

  override _transform(chunk: any, _encoding: BufferEncoding, callback: TransformCallback) {
    let data = chunk as Buffer
    if (this.inputEncoding) {
      data = Buffer.from(data.toString(), this.inputEncoding)
    }
    if (!this.decipher) {
      // Unpackage the combined iv + encrypted message.
      // Since we are using a fixed size IV, we can hard code the slice length.
      const iv = data.subarray(0, this.ivLength)
      this.decipher = crypto.createDecipheriv(this.algo, this.cipherKey, iv)
      data = data.subarray(this.ivLength)
    }
    this.push(this.decipher.update(data))
    callback()
  }

  override _flush(callback: TransformCallback) {
    this.push(this.decipher?.final())
    callback()
  }
}
