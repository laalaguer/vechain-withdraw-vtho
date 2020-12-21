from thor_devkit import abi
from thor_devkit import cry
from thor_devkit import transaction
from thor_devkit.cry import mnemonic
from thor_devkit.cry import secp256k1
import requests
import random
import json
import argparse

# Main-net and test-net
MAIN_NET = 'https://sync-mainnet.vechain.org/'
TEST_NET = 'https://sync-testnet.vechain.org/'

# Main-net and test-net
MAIN_NET_CHAIN_TAG = int('0x4a', 16)
TEST_NET_CHAIN_TAG = int('0x27', 16)

# Built-in contracts on both main-net and test-net.
ENERGY = '0x0000000000000000000000000000456e65726779'
PROTOTYPE = '0x000000000000000000000050726f746f74797065'

# Some on-chain functions we gonna use.
FUNC_FIND_MASTER = {
    "constant": True,
    "inputs": [
        {
            "name": "_self",
            "type": "address"
        }
    ],
    "name": "master",
    "outputs": [
        {
            "name": "",
            "type": "address"
        }
    ],
    "payable": False,
    "stateMutability": "view",
    "type": "function"
}

FUNC_CHECK_VTHO_BALANCE = {
    "constant": True,
    "inputs": [
        {
            "name": "_owner",
            "type": "address"
        }
    ],
    "name": "balanceOf",
    "outputs": [
        {
            "name": "balance",
            "type": "uint256"
        }
    ],
    "payable": False,
    "stateMutability": "view",
    "type": "function"
}

FUNC_MOVE_VTHO = {
    "constant": False,
    "inputs": [
        {
            "name": "_from",
            "type": "address"
        },
        {
            "name": "_to",
            "type": "address"
        },
        {
            "name": "_amount",
            "type": "uint256"
        }
    ],
    "name": "move",
    "outputs": [
        {
            "name": "success",
            "type": "bool"
        }
    ],
    "payable": False,
    "stateMutability": "nonpayable",
    "type": "function"
}

# simulate is enough.
def find_master():
    return abi.Function(abi.FUNCTION(FUNC_FIND_MASTER))

# simulate is enough.
def get_vtho_balance():
    return abi.Function(abi.FUNCTION(FUNC_CHECK_VTHO_BALANCE))

# need real vtho to execute it.
def move_vtho():
    return abi.Function(abi.FUNCTION(FUNC_MOVE_VTHO))


def build_clause_data(abi_func, abi_params: list):
    ''' Send requests to vechain and get response '''
    data = abi_func().encode(abi_params, to_hex=True)
    return data


def decode_return_data(abi_func, log_data_hex: str) -> dict:
    ''' Decode log_data_hex (without 0x prefix) '''
    return abi_func.decode(bytes.fromhex(log_data_hex))


def _get_public_node(network='main'):
    if network == 'main':
        return MAIN_NET
    if network == 'test':
        return TEST_NET
    raise Exception(f"network {network} unknown")


def _get_chain_tag(network='main'):
    if network == 'main':
        return MAIN_NET_CHAIN_TAG
    if network == 'test':
        return TEST_NET_CHAIN_TAG
    raise Exception(f"network {network} unknown")


def get_latest_block_id(network='main'):
    url = _get_public_node(network)
    r = requests.get(url + 'blocks/best')
    return r.json().get('id')


def get_block_ref(network='main'):
    previous_block_id = get_latest_block_id(network)
    return previous_block_id[0:18]


def _sign(private_key: bytes, message_hash: bytes):
    return cry.secp256k1.sign(message_hash, private_key)


def simulate_execute(network: str, tx_body: dict):
    url = _get_public_node(network)
    # print(tx_body)
    r = requests.post(url + 'accounts/*', data=json.dumps(tx_body))
    if r.status_code != 200:
        raise Exception(r.text)
    return r.json()

def real_execute(network: str, raw_hex: str):
    url = _get_public_node(network)
    r = requests.post(url + 'transactions', data=json.dumps({
        'raw': raw_hex
    }))
    if r.status_code != 200:
        raise Exception(r.text)
    return r.json()

def check_vtho_balance_of(addr: str, caller: str, network: str) -> int:
    ''' VTHO balance of an address, in wei '''
    body = {
        #"chainTag": _get_chain_tag(network)
        "blockRef": get_block_ref(network),
        "expiration": 32,
        "clauses": [
            {
                "to": ENERGY,
                "value": '0x00',
                "data": build_clause_data(get_vtho_balance, [addr])
            }
        ],
        #"gasPriceCoef": 0,
        "gas": 21000,
        #"dependsOn": None,
        #"nonce": random.randint(0, 2 ** 64)
        "caller": caller,
        "gasPayer": caller,
    }

    data = simulate_execute(network, body)[0]['data']
    decoded = get_vtho_balance().decode(bytes.fromhex(data[2:]))
    return int(decoded['0'])


def check_master_of(contract_addr: str, caller: str, network: str) -> str:
    ''' Check the master of the smart contract '''
    body = {
        #"chainTag": _get_chain_tag(network)
        "blockRef": get_block_ref(network),
        "expiration": 32,
        "clauses": [
            {
                "to": PROTOTYPE,
                "value": '0x00',
                "data": build_clause_data(find_master, [contract_addr])
            }
        ],
        #"gasPriceCoef": 0,
        "gas": 21000,
        #"dependsOn": None,
        #"nonce": random.randint(0, 2 ** 64)
        "caller": caller,
        "gasPayer": caller,
    }

    data = simulate_execute(network, body)[0]['data']
    decoded = find_master().decode(bytes.fromhex(data[2:]))
    return str(decoded['0'])


def simulate_move(from_addr: str, to_addr: str, amount: int, caller: str, network: str) -> int:
    ''' Simulate the move, if success, return the gas needed '''
    body = {
        #"chainTag": _get_chain_tag(network)
        "blockRef": get_block_ref(network),
        "expiration": 32,
        "clauses": [
            {
                "to": ENERGY,
                "value": '0x00',
                "data": build_clause_data(move_vtho, [from_addr, to_addr, amount])
            }
        ],
        #"gasPriceCoef": 0,
        "gas": 60000,
        #"dependsOn": None,
        #"nonce": random.randint(0, 2 ** 64)
        "caller": caller,
        "gasPayer": caller,
    }

    j = simulate_execute(network, body)
    if j[0]['reverted']:
        print(j)
        raise Exception('reverted!')
    
    return j[0]['gasUsed']


def do_move(from_addr: str, to_addr: str, amount: int, private_key: bytes, network: str):
    body = {
        "chainTag": _get_chain_tag(network),
        "blockRef": get_block_ref(network),
        "expiration": 32,
        "clauses": [
            {
                "to": ENERGY,
                "value": '0x00',
                "data": build_clause_data(move_vtho, [from_addr, to_addr, amount])
            }
        ],
        "gasPriceCoef": 0,
        "gas": 60000,
        "dependsOn": None,
        "nonce": random.randint(0, 2 ** 64)
    }
    tx = transaction.Transaction(body)
    message_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(message_hash, private_key)
    tx.set_signature(signature)
    raw_hex = '0x' + tx.encode().hex()

    return real_execute(network, raw_hex)


def run(private_key: bytes, target: str, network: str):
    public_key = secp256k1.derive_publicKey(private_key)
    _address_bytes = cry.public_key_to_address(public_key)
    my_address = '0x' + _address_bytes.hex()

    print(f"Target contract address: {target}")
    print(f"Your address: {my_address}")
    print(f"Working on: {network}-net")
    print("#" * 30)

    target_vtho_in_wei = check_vtho_balance_of(target, my_address, network)
    print(f"Target has: {target_vtho_in_wei / (10**18)} vtho")

    if target_vtho_in_wei == 0:
        print("Target contract doesn't have vtho, abort!")
        exit()

    my_vtho_in_wei = check_vtho_balance_of(my_address, my_address, network)
    print(f"You have: {my_vtho_in_wei / (10**18)} vtho")

    # At least 60 vtho is needed to call move()
    if my_vtho_in_wei / (10 ** 18) < 60:
        print("You need at least 60 vtho to call move(), abort!")
        exit()

    print()

    master_of_target = check_master_of(target, my_address, network)
    print(f"Target's master: {master_of_target}")

    if master_of_target.lower() != my_address.lower():
        print("Target's master is NOT you. Abort!")
        exit(1)

    # Do a round of simulation on move(). Check if can pass the simulation.
    simulate_move(target, my_address, target_vtho_in_wei, my_address, network)

    # Do the real move()
    do_move(target, my_address, target_vtho_in_wei, private_key, network)

def start(args):
    ### Get the private key from user input ###
    if (not args.words) and (not args.privatekey):
        print("You should either specify --words or --privatekey")
        exit()

    if args.words and args.privatekey:
        print("You can only specify one of the --words or --privatekey")
        exit()
    
    private_key = None
    if args.words:
        words = args.words.split()
        private_key = mnemonic.derive_private_key(words)
    if args.privatekey:
        if len(args.privatekey) != 64:
            print("Private key shall be 64 chars!")
            exit()
        private_key = bytes.fromhex(args.privatekey)

    ### Get target contract address from user input ###
    target = args.target
    if not cry.is_address(target):
        print("target shall be 0x..., an address style")
        exit()

    ### Get main net or test net from user input ###
    network = args.net
    if not network in ['main', 'test']:
        print("--net shall be main or test")
        exit()

    print("#" * 30)
    run(private_key, target, network)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    cmd_parser = subparsers.add_parser('drain')
    # from which target contract to drain the vtho
    cmd_parser.add_argument('target')
    # private key from the user.
    cmd_parser.add_argument('--words', default='')
    cmd_parser.add_argument('--privatekey', default='')
    # mainnet or testnet?
    cmd_parser.add_argument('--net', default='main')

    cmd_parser.set_defaults(func=start)

    args = parser.parse_args()
    args.func(args)