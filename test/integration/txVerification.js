import { before, describe, it } from 'mocha'
import { getSdk } from '.'
import { generateKeyPair } from '../../src/utils/crypto'
import { BASE_VERIFICATION_SCHEMA, SIGNATURE_VERIFICATION_SCHEMA } from '../../src/tx/builder/schema'
import MemoryAccount from '../../src/account/memory'

const WARNINGS = [...SIGNATURE_VERIFICATION_SCHEMA, ...BASE_VERIFICATION_SCHEMA].reduce((acc, [msg, v, error]) => error.type === 'warning' ? [...acc, error.txKey] : acc, [])
const ERRORS = [...BASE_VERIFICATION_SCHEMA, ...SIGNATURE_VERIFICATION_SCHEMA].reduce((acc, [msg, v, error]) => error.type === 'error' ? [...acc, error.txKey] : acc, [])
const channelCreate = 'tx_+IgyAqEBA36iFX3O+BMXMZJbffeT423KLpEuFsISUTsGu8Sb10eJBWvHXi1jEAAAoQGTnVZ1Jow5NGyBOg3NAf+ie3mV8qDj/wBwyKBHFNdhT4kFa8deLWMQAAAAAQCGECcSfcAAwMCgGAbROhx5lfoSkXsM5MQLw+EAWei3pcUGj/zWSO8RGkAKfIRASg=='

describe('Verify Transaction', function () {
  let client

  before(async () => {
    client = await getSdk()
    await client.spend(1234, 'ak_LAqgfAAjAbpt4hhyrAfHyVg9xfVQWsk1kaHaii6fYXt6AJAGe')
  })
  it('validate params', async () => {
    return client.spendTx({}).should.be.rejectedWith({
      code: 'TX_BUILD_VALIDATION_ERROR',
      msg: 'Validation error'
    })
  })
  it('check warnings', async () => {
    const spendTx = await client.spendTx({
      senderId: await client.address(),
      recipientId: await client.address(),
      amount: '1242894753985394725983479583427598237459328752353245345',
      nonce: '100',
      ttl: 2,
      absoluteTtl: true
    })

    const { validation } = await client.unpackAndVerify(spendTx)
    const warning = validation
      .filter(({ type }) => type === 'warning')
      .map(({ txKey }) => txKey)

    WARNINGS.should.be.eql(warning)
  })
  it('check errors', async () => {
    const spendTx = await client.spendTx({
      senderId: await client.address(),
      recipientId: await client.address(),
      amount: 1,
      fee: '1000',
      nonce: '1',
      ttl: 2,
      absoluteTtl: true
    })

    await client.addAccount(MemoryAccount({ keypair: generateKeyPair() }), { select: true })
    // Sign using another account
    const signedTx = await client.signTransaction(spendTx)

    const { validation } = await client.unpackAndVerify(signedTx)
    const error = validation
      .filter(({ type }) => type === 'error') // exclude contract vm/abi, has separated test for it
      .map(({ txKey }) => txKey)

    ERRORS.filter(e => e !== 'gasPrice' && e !== 'ctVersion').should.be.eql(error)
  })
  it('verify transaction before broadcast', async () => {
    client = await getSdk()
    const spendTx = await client.spendTx({
      senderId: await client.address(),
      recipientId: await client.address(),
      amount: 1,
      ttl: 2,
      absoluteTtl: true
    })

    try {
      await client.send(spendTx, { verify: true })
    } catch ({ errorData }) {
      const atLeastOneError = !!errorData.validation.length
      atLeastOneError.should.be.equal(true)
    }
  })
  it('Verify vmVersion/abiVersion for contract transactions', async () => {
    // Contract create transaction with wrong abi/vm version (vm: 3, abi: 0)
    const contractCreateTx = 'tx_+QSaKgGhASLDuRmSBJZv91HE219uqXb2L0adh+bilzBWUi93m5blArkD+PkD9UYCoI2tdssfNdXZOclcaOwkTNB2S/SXIVsLDi7KUoxJ3Jki+QL7+QEqoGjyZ2M4/1CIOaukd0nv+ovofvKE8gf7PZmYcBzVOIfFhG1haW64wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACg//////////////////////////////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPkBy6C5yVbyizFJqfWYeqUF89obIgnMVzkjQAYrtsG9n5+Z6oRpbml0uGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//////////////////////////////////////////+5AUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAP//////////////////////////////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////////////////////////////////////7jMYgAAZGIAAISRgICAUX+5yVbyizFJqfWYeqUF89obIgnMVzkjQAYrtsG9n5+Z6hRiAADAV1CAUX9o8mdjOP9QiDmrpHdJ7/qL6H7yhPIH+z2ZmHAc1TiHxRRiAACvV1BgARlRAFtgABlZYCABkIFSYCCQA2ADgVKQWWAAUVlSYABSYADzW2AAgFJgAPNbWVlgIAGQgVJgIJADYAAZWWAgAZCBUmAgkANgA4FSgVKQVltgIAFRUVlQgJFQUICQUJBWW1BQgpFQUGIAAIxWhTIuMS4wgwMAAIcF9clYKwgAAAAAgxgX+IQ7msoAuGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAILnJVvKLMUmp9Zh6pQXz2hsiCcxXOSNABiu2wb2fn5nqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkansY'
    const { validation } = await client.unpackAndVerify(contractCreateTx)
    const vmAbiError = validation.find(el => el.txKey === 'ctVersion')
    vmAbiError.msg.split(',')[0].should.be.equal('Wrong abi/vm version')
  })
  it('Verify channel create tx', async () => {
    const res = await client.unpackAndVerify(channelCreate)
    Array.isArray(res.validation).should.be.equal(true)
  })
  it('Verify nameFee for nameClaim transaction', async () => {
    const tx = 'tx_+KILAfhCuEAtbc38n/FH8jZHO0DkEkiLZZm8ypEzZEhbjyHtaoEYkENOE9tD+Xp6smFMou9X521oI4gkFBQGwSQaQk6Z7XMNuFr4WCACoQHkWpoidhJW2EZEega88I1P9Ktw1DFBUWwrzkr5jC5zUAORc29tZUF1Y3Rpb24uY2hhaW6HDwTrMteR15AJQ0VVyE5TcqKSstgfbGV6hg9HjghAAAAGpIPS'
    const res = await client.unpackAndVerify(tx)
    const nameFeeError = res.validation.find(err => err.txKey === 'nameFee')
    nameFeeError.should.be.an('object')
    nameFeeError.type.should.be.equal('error')
    nameFeeError.msg.indexOf('The account balance').should.not.be.equal(-1)
  })
})
