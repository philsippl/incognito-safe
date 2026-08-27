//! Minimal, compile-time checked ABIs for the Safe contracts used by the CLI.

// `ISafe.setup` necessarily has the nine arguments defined by the upstream ABI.
#![allow(clippy::too_many_arguments)]

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface ISafeProxyFactory {
        function proxyCreationCode() external pure returns (bytes memory);
        function createProxyWithNonceL2(
            address singleton,
            bytes memory initializer,
            uint256 saltNonce
        ) external returns (address proxy);
        function createChainSpecificProxyWithNonceL2(
            address singleton,
            bytes memory initializer,
            uint256 saltNonce
        ) external returns (address proxy);
    }

    #[sol(rpc)]
    interface ISafe {
        function setup(
            address[] calldata owners,
            uint256 threshold,
            address to,
            bytes calldata data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address payable paymentReceiver
        ) external;
        function getOwners() external view returns (address[] memory);
        function getThreshold() external view returns (uint256);
        function VERSION() external view returns (string memory);
    }

    interface ISafeToL2Setup {
        function setupToL2(address l2Singleton) external;
    }

    #[sol(rpc)]
    interface ISafeProxy {
        function masterCopy() external view returns (address);
    }
}
