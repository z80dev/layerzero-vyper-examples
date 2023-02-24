PAYLOAD_SIZE: constant(uint256) = 128
CONFIG_SIZE: constant(uint256) = 512

@internal
def _nonblockingLzReceive(_srcChainId: uint16, _srcAddress: Bytes[40], _nonce: uint64, _payload: Bytes[PAYLOAD_SIZE]):
    # contract body upon cross-chain call goes here
    pass

failedMessages: public(HashMap[uint16, HashMap[Bytes[40], HashMap[uint64, bytes32]]])

event MessageFailed:
    _srcChainId: uint16
    _srcAddress: Bytes[40]
    _nonce: uint64
    _payload: Bytes[PAYLOAD_SIZE]
    _reason: Bytes[1024]


event RetryMessageSuccess:
    _srcChainId: uint16
    _srcAddress: Bytes[40]
    _nonce: uint64
    _payloadHash: bytes32

# filler implementation of _blockingLzReceive
# body is just a `pass` statement
@internal
def _blockingLzReceive(_srcChainId: uint16, _srcAddress: Bytes[40], _nonce: uint64, _payload: Bytes[PAYLOAD_SIZE]):
    # call self via raw_call with revert_on_failure=False and max_outsize=256
    # raw_call signature is pasted below
    # raw_call(to: address, data: Bytes, max_outsize: int = 0, gas: uint256 = gasLeft, value: uint256 = 0, is_delegate_call: bool = False, is_static_call: bool = False, revert_on_failure: bool = True)→ Bytes[max_outsize]
    success: bool = False
    data: Bytes[256] = b""
    success, data = raw_call(self, concat(0x66ad5c8a, _abi_encode(_srcChainId, _srcAddress, _nonce, _payload)), max_outsize=256, revert_on_failure=False)
    if not success:
        self._storeFailedMessage(_srcChainId, _srcAddress, _nonce, _payload)

# implementation of _storeFailedMessage
@internal
def _storeFailedMessage(_srcChainId: uint16, _srcAddress: Bytes[40], _nonce: uint64, _payload: Bytes[PAYLOAD_SIZE]):
    payloadHash: bytes32 = keccak256(_payload)
    self.failedMessages[_srcChainId][_srcAddress][_nonce] = payloadHash
    log MessageFailed(_srcChainId, _srcAddress, _nonce, _payload, convert("Failed to send payload", Bytes[100]))

@external
def nonblockingLzReceive(_srcChainId: uint16, _srcAddress: Bytes[40], _nonce: uint64, _payload: Bytes[PAYLOAD_SIZE]):
    assert msg.sender == self, "ONLYSELF"
    self._nonblockingLzReceive(_srcChainId, _srcAddress, _nonce, _payload)

interface ILayerZeroReceiver:
    def lzReceive(srcChainId: uint16, srcAddress: Bytes[40], nonce: uint64, payload: Bytes[PAYLOAD_SIZE]): nonpayable

interface ILayerZeroEndpoint:
    # def send(dstChainId: uint16, destination: Bytes[40], payload: Bytes[CONFIG_SIZE], refundAddress: address, zroPaymentAddress: address, adapterParams: Bytes[CONFIG_SIZE]): payable
    def receivePayload(srcChainId: uint16, srcAddress: Bytes[40], dstAddress: address, nonce: uint64, gasLimit: uint256, payload: Bytes[PAYLOAD_SIZE]): nonpayable
    def getInboundNonce(srcChainId: uint16, srcAddress: Bytes[40]) -> uint64: view
    def getOutboundNonce(dstChainId: uint16, srcAddress: address) -> uint64: view
    def estimateFees(dstChainId: uint16, userApplication: address, payload: Bytes[PAYLOAD_SIZE], payInZRO: bool, adapterParam: Bytes[CONFIG_SIZE]) -> (uint256, uint256): view
    def getChainId() -> uint16: view
    def retryPayload(srcChainId: uint16, srcAddress: Bytes[40], payload: Bytes[PAYLOAD_SIZE]): nonpayable
    def hasStoredPayload(srcChainId: uint16, srcAddress: Bytes[40]) -> bool: view
    def getSendLibraryAddress(userApplication: address) -> address: view
    def getReceiveLibraryAddress(userApplication: address) -> address: view
    def isSendingPayload() -> bool: view
    def isReceivingPayload() -> bool: view
    def getConfig(version: uint16, chainId: uint16, userApplication: address, configType: uint256) -> Bytes[CONFIG_SIZE]: view
    def getSendVersion(userApplication: address) -> uint16: view
    def getReceiveVersion(userApplication: address) -> uint16: view
    def setConfig(version: uint16, chainId: uint16, configType: uint256, config: Bytes[CONFIG_SIZE]): nonpayable
    def setSendVersion(version: uint16): nonpayable
    def setReceiveVersion(version: uint16): nonpayable
    def forceResumeReceive(srcChainId: uint16, srcAddress: Bytes[40]): nonpayable

interface ILayerZeroMessagingLibrary:
    # def send(_userApplication: address, _lastNonce: uint64, _chainId: uint16, _destination: Bytes[40], _payload: Bytes[CONFIG_SIZE], refundAddress: address, _zroPaymentAddress: address, _adapterParams: Bytes[CONFIG_SIZE]): payable
    def estimateFees(_chainId: uint16, _userApplication: address, _payload: Bytes[PAYLOAD_SIZE], _payInZRO: bool, _adapterParam: Bytes[CONFIG_SIZE]) -> (uint256, uint256): view
    def setConfig(_chainId: uint16, _userApplication: address, _configType: uint256, _config: Bytes[CONFIG_SIZE]): nonpayable
    def getConfig(_chainId: uint16, _userApplication: address, _configType: uint256) -> Bytes[CONFIG_SIZE]: view

interface ILayerZeroOracle:
    def getPrice(dstChainId: uint16, outboundProofType: uint16) -> uint256: view
    def notifyOracle(dstChainId: uint16, outboundProofType: uint16, outboundBlockConfirmations: uint64): nonpayable
    def isApproved(_address: address) -> bool: view

interface ILayerZeroRelayer:
    def getPrice(dstChainId: uint16, outboundProofType: uint16, userApplication: address, payloadSize: uint256, adapterParams: Bytes[CONFIG_SIZE]) -> uint256: view
    def notifyRelayer(dstChainId: uint16, outboundProofType: uint16, adapterParams: Bytes[CONFIG_SIZE]): nonpayable
    def isApproved(_address: address) -> bool: view

owner: address

lzEndpoint: public(ILayerZeroEndpoint)
DEFAULT_PAYLOAD_SIZE_LIMIT: constant(uint256) = 1000000
trustedRemoteLookup: public(HashMap[uint16, Bytes[40]])
payloadSizeLimitLookup: public(HashMap[uint16, uint256])
minDstGasLookup: public(HashMap[uint16, HashMap[uint16, uint256]])
precrime: public(address)

event SetPrecrime:
    precrime: address

event SetTrustedRemote:
    _remoteChainId: uint16
    _path: Bytes[40]

event SetTrustedRemoteAddress:
    _remoteChainId: uint16
    _remoteAddress: Bytes[20]

event SetMinDstGas:
    _dstChainId: uint16
    _type: uint16
    _minDstGas: uint256

@external
def __init__(_lzEndpoint: ILayerZeroEndpoint):
    self.lzEndpoint = _lzEndpoint
    self.owner = msg.sender

@internal
def _onlyOwner():
    assert msg.sender == self.owner

@external
def lzReceive(_srcChainId: uint16, _srcAddress: Bytes[40], _nonce: uint64, _payload: Bytes[PAYLOAD_SIZE]):
    assert msg.sender == self.lzEndpoint.address
    trustedRemote: Bytes[40] = self.trustedRemoteLookup[_srcChainId]
    assert len(_srcAddress) == len(trustedRemote)
    assert len(trustedRemote) > 0
    assert keccak256(_srcAddress) == keccak256(trustedRemote)

    self._blockingLzReceive(_srcChainId, _srcAddress, _nonce, _payload)


@internal
def _lzSend(_dstChainId: uint16, _payload: Bytes[PAYLOAD_SIZE], _refundAddress: address, _zroPaymentAddress: address, _adapterParams: Bytes[CONFIG_SIZE], _nativeFee: uint256):
    trustedRemote: Bytes[40] = self.trustedRemoteLookup[_dstChainId]
    assert len(trustedRemote) != 0
    self._checkPayloadSize(_dstChainId, len(_payload))
    # usually, we would call the send function like this
    # self.lzEndpoint.send(_dstChainId, trustedRemote, _payload, _refundAddress, _zroPaymentAddress, _adapterParams, value=_nativeFee)
    #
    # the interface definition for this function in solidity is:
    #     function send(uint16 _dstChainId, bytes calldata _destination, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) external payable;

    #
    # because send is a reserved keyword in Vyper, we have to use raw_call to call this function
    # we will use _abiEncode to encode the arguments to be passed

    # encode the arguments
    payload: Bytes[2404] = _abi_encode(_dstChainId, trustedRemote, _payload, _refundAddress, _zroPaymentAddress, _adapterParams, method_id=method_id("send(uint16,bytes,bytes,address,address,bytes)"))
    # call the function
    raw_call(self.lzEndpoint.address, payload, value=_nativeFee)


@external
def _checkGasLimit(_dstChainId: uint16, _type: uint16, _adapterParams: Bytes[CONFIG_SIZE], _extraGas: uint256):
    providedGasLimit: uint256 = self._getGasLimit(_adapterParams)
    minGasLimit: uint256 = self.minDstGasLookup[_dstChainId][_type] + _extraGas
    assert minGasLimit > 0, "LzApp: minGasLimit not set"
    assert providedGasLimit >= minGasLimit, "LzApp: gas limit is too low"


@internal
@pure
def _getGasLimit(_adapterParams: Bytes[CONFIG_SIZE]) -> uint256:
    assert len(_adapterParams) >= 34
    return convert(slice(_adapterParams, 34, 32), uint256)

@internal
def _checkPayloadSize(_dstChainId: uint16, _payloadSize: uint256):
    payloadSizeLimit: uint256 = self.payloadSizeLimitLookup[_dstChainId]
    if payloadSizeLimit == 0:
        payloadSizeLimit = DEFAULT_PAYLOAD_SIZE_LIMIT
    assert _payloadSize <= payloadSizeLimit, "LzApp: payload size is too large"

@external
def getConfig(_version: uint16, _chainId: uint16, _configType: uint256) -> Bytes[CONFIG_SIZE]:
    return self.lzEndpoint.getConfig(_version, _chainId, self, _configType)

@external
def setConfig(_version: uint16, _chainId: uint16, _configType: uint256, _config: Bytes[CONFIG_SIZE]):
    self._onlyOwner()
    self.lzEndpoint.setConfig(_version, _chainId, _configType, _config)

@external
def setSendVersion(_version: uint16):
    self._onlyOwner()
    self.lzEndpoint.setSendVersion(_version)

@external
def setReceiveVersion(_version: uint16):
    self._onlyOwner()
    self.lzEndpoint.setReceiveVersion(_version)

@external
def forceResumeReceive(_srcChainId: uint16, _srcAddress: Bytes[40]):
    self.lzEndpoint.forceResumeReceive(_srcChainId, _srcAddress)

@external
def setTrustedRemote(_srcChainId: uint16, _path: Bytes[40]):
    self._onlyOwner()
    self.trustedRemoteLookup[_srcChainId] = _path
    log SetTrustedRemote(_srcChainId, _path)

@external
def setTrustedRemoteAddress(_remoteChainId: uint16, _remoteAddress: address):
    # convert address to bytes
    _remoteAddressBytes: Bytes[20] = slice(concat(b"", convert(_remoteAddress, bytes32)), 12, 20)
    selfAddrAsBytes: Bytes[20] = slice(concat(b"", convert(self, bytes32)), 12, 20)
    self.trustedRemoteLookup[_remoteChainId] = concat(_remoteAddressBytes, selfAddrAsBytes)
    log SetTrustedRemoteAddress(_remoteChainId, _remoteAddressBytes)

@external
@view
def getTrustedRemoteAddress(_remoteChainId: uint16) -> Bytes[20]:
    path: Bytes[40] = self.trustedRemoteLookup[_remoteChainId]
    assert len(path) != 0
    return slice(path, 0, 20)

@external
def setPrecrime(precrime: address):
    self._onlyOwner()
    self.precrime = precrime
    log SetPrecrime(precrime)

@external
def setMinDstGas(_dstChainId: uint16, _packetType: uint16, _minGas: uint256):
    self._onlyOwner()
    assert _minGas > 0, "LzApp: invalid minGas"
    self.minDstGasLookup[_dstChainId][_packetType] = _minGas
    log SetMinDstGas(_dstChainId, _packetType, _minGas)

@external
@view
def isTrustedRemote(_srcChainId: uint16, _srcAddress: Bytes[40]) -> bool:
    trustedSource: Bytes[40] = self.trustedRemoteLookup[_srcChainId]
    return keccak256(trustedSource) == keccak256(_srcAddress)
