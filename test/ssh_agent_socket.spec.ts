import * as chai from 'chai'
import { describe, it } from 'mocha'
import { existsSync, unlinkSync } from 'node:fs'
import chaiAsPromised from 'chai-as-promised'
import { createServer } from 'node:net'
import { SSHAgentClient } from '../src/lib/ssh_agent_client.ts'

chai.use(chaiAsPromised)

describe('SSH Agent socket tests', () => {
  const sockPath = '/tmp/ssh_agent_mock.test.sock'

  afterEach(() => {
    if (existsSync(sockPath)) {
      unlinkSync(sockPath)
    }
  })

  it("should timeout if socket doesn't respond", done => {
    const server = createServer()
    server.listen(sockPath)
    const agent = new SSHAgentClient({ sockFile: sockPath, timeout: 25 })
    chai
      .expect(agent.getIdentities())
      .to.be.rejectedWith(Error, 'Request timed out after 25 ms')
      .and.notify((err: Error) => {
        server.close()
        done(err)
      })
  })

  it('should throw if invalid frame length 0x0001', done => {
    const server = createServer(socket => {
      socket.on('data', () => {
        const res = Buffer.allocUnsafe(4)
        res.writeUint32BE(1)
        socket.write(res)
      })
    })
    server.listen(sockPath)
    const agent = new SSHAgentClient({ sockFile: sockPath, timeout: 25 })
    chai
      .expect(agent.getIdentities())
      .to.be.rejectedWith(Error, 'InvalidProtocolError: Expected frame length 1, got 0')
      .and.notify((err: Error) => {
        server.close()
        done(err)
      })
  })

  it('should throw if unexpected message type', done => {
    const server = createServer(socket => {
      socket.on('data', () => {
        const res = Buffer.allocUnsafe(5)
        res.writeUint32BE(1)
        res.writeUint8(99, 4)
        socket.write(res)
      })
    })
    server.listen(sockPath)
    const agent = new SSHAgentClient({ sockFile: sockPath, timeout: 25 })
    chai
      .expect(agent.getIdentities())
      .to.be.rejectedWith(Error, 'InvalidProtocolError: Expected message type 12, got 99')
      .and.notify((err: Error) => {
        server.close()
        done(err)
      })
  })

  it('should throw if unexpected response format', done => {
    const server = createServer(socket => {
      socket.on('data', () => {
        const res = Buffer.allocUnsafe(9)
        res.writeUint32BE(5)
        res.writeUint8(12, 4)
        res.writeUint32BE(1, 5)
        socket.write(res)
      })
    })
    server.listen(sockPath)
    const agent = new SSHAgentClient({ sockFile: sockPath, timeout: 25 })
    chai
      .expect(agent.getIdentities())
      .to.be.rejectedWith(
        Error,
        'The value of "offset" is out of range. It must be >= 0 and <= 0. Received 4',
      )
      .and.notify((err: Error) => {
        server.close()
        done(err)
      })
  })

  it('should throw if socket close', done => {
    const server = createServer(socket => {
      socket.on('data', () => {
        socket.end()
      })
    })
    server.listen(sockPath)
    const agent = new SSHAgentClient({ sockFile: sockPath, timeout: 25 })
    chai
      .expect(agent.getIdentities())
      .to.be.rejectedWith(Error, 'InvalidProtocolError: No response from SSH agent')
      .and.notify((err: Error) => {
        server.close()
        done(err)
      })
  })
})
