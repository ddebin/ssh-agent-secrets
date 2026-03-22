import { assert } from 'chai'
import { describe, it } from 'mocha'
import { SSHAgentClient } from '../src/ssh_agent_client'

describe('SSHAgentClient Tests', () => {
  it('should throw for incorrect socket', () => {
    assert.throw(
      () =>
        new SSHAgentClient({
          sockFile: '/tmp/non_existent.sock',
        }),
    )
  })
  it('should find identites', async () => {
    const agent = new SSHAgentClient()
    const identities = await agent.requestIdentities()
    assert.equal(3, identities.length)
  })
})
