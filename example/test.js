import { SSHAgentClient } from '../dist/src/lib/index.js'

const agent = new SSHAgentClient()

const identities = await agent.getIdentities()
console.log(`${identities.length} identities found in the SSH agent`)

// replace "AWS" with the actual comment of your SSH key
const identity = await agent.getIdentity('ED25519')

const encrypted = await agent.encrypt(
  identity,
  'not_a_secret_but_a_seed',
  Buffer.from('Lorem ipsum dolor', 'utf8'),
  'hex',
)
console.log('Encrypted data:', encrypted)

const decrypted = await agent.decrypt(identity, 'not_a_secret_but_a_seed', encrypted, 'hex')
console.log('Decrypted data:', decrypted.toString('utf8'))
