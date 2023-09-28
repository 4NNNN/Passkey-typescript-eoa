import * as Type from './solidity-types'

export default interface UserOperation {
  txType: Type.uint256
  from: Type.uint256
  to: Type.uint256
  gasLimit:Type.uint256
  gasPerPubdataByteLimit: Type.uint256
  maxFeePerGas: Type.uint256
  maxPriorityFeePerGas: Type.uint256
  paymaster: Type.uint256
  nonce: Type.uint256
  value: Type.uint256
  reserved: Type.uint256[]
  data: Type.bytes
  signature: Type.bytes
  factoryDeps:Type.bytes32[]
  paymasterInput:Type.bytes
  reservedDynamic:Type.bytes
}