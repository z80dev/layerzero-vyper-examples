// import LZEndpointMock
import "@layerzero/mocks/LZEndpointMock.sol";

contract EndpointMock is LZEndpointMock {
    constructor(uint16 _id) LZEndpointMock(_id) {}
}
