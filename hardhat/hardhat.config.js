require('@nomicfoundation/hardhat-toolbox');

// Disposable test chain only. No localhost/Tailscale/Public RPC network is configured.
module.exports = {
  solidity: '0.8.28',
  networks: {
    hardhat: { chainId: 31337 }
  }
};
