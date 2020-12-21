# Purpose
Widthdraw the vtho stucked in a smart contract.

# Background
VeChain has a two-token system that enables an external address or a smart contract to hold VTHO.

Less known to the public is that these VTHO stuck in a smart contract can be widthdrawn from it, by
the `master` of the smart contract who is, by defaut, the creator of the smart contract.

So, with a `private key` of the creator, and the `address` of the smart contract, we can withdraw VTHO from it.

This tool provides a script to widthdraw it easily.

# Install

`pip3 install -r requirements.txt`

# Usage

Withdraw all VTHO from contract with private key:

`python3 withdraw.py drain {contract_address} --privatekey={private_key} `

Withdraw all VTHO from contract with mnemonic words:

`python3 withdraw.py drain {contract_address} --words="apple banana cat ..."`