#!/usr/bin/env python3

import argparse
import requests
import json
import math

from bitcoinx import (
        PrivateKey, TxOutput, TxInput, Tx,
        Script, SigHash, pack_byte, PublicKey
        )

import scryptlib
from scryptlib.types import *


contract = './vanityAddr.scrypt'
compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

VanityAddr = scryptlib.build_contract_class(desc)


b58_rev_alpha = {
    '1': b'\x00',
    '2': b'\x01',
    '3': b'\x02',
    '4': b'\x03',
    '5': b'\x04',
    '6': b'\x05',
    '7': b'\x06',
    '8': b'\x07',
    '9': b'\x08',
    'A': b'\x09',
    'B': b'\x0a',
    'C': b'\x0b',
    'D': b'\x0c',
    'E': b'\x0d',
    'F': b'\x0e',
    'G': b'\x0f',
    'H': b'\x10',
    'J': b'\x11',
    'K': b'\x12',
    'L': b'\x13',
    'M': b'\x14',
    'N': b'\x15',
    'P': b'\x16',
    'Q': b'\x17',
    'R': b'\x18',
    'S': b'\x19',
    'T': b'\x1a',
    'U': b'\x1b',
    'V': b'\x1c',
    'W': b'\x1d',
    'X': b'\x1e',
    'Y': b'\x1f',
    'Z': b'\x20',
    'a': b'\x21',
    'b': b'\x22',
    'c': b'\x23',
    'd': b'\x24',
    'e': b'\x25',
    'f': b'\x26',
    'g': b'\x27',
    'h': b'\x28',
    'i': b'\x29',
    'j': b'\x2a',
    'k': b'\x2b',
    'm': b'\x2c',
    'n': b'\x2d',
    'o': b'\x2e',
    'p': b'\x2f',
    'q': b'\x30',
    'r': b'\x31',
    's': b'\x32',
    't': b'\x33',
    'u': b'\x34',
    'v': b'\x35',
    'w': b'\x36',
    'x': b'\x37',
    'y': b'\x38',
    'z': b'\x39',
    }


def derive_contract_pubkeys(k):
    res = []

    # No sym, no endo
    res.append(k.public_key)

    # No sym, endo 1
    lambda1 = PrivateKey.from_hex('5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72')
    e = k.multiply(lambda1._secret)
    res.append(e.public_key)

    # No sym, endo 2
    lambda2 = PrivateKey.from_hex('ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce')
    e = k.multiply(lambda2._secret)
    res.append(e.public_key)

    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    # Sym, no endo
    e = PrivateKey.from_int((k.to_int() * -1 + order) % p)
    res.append(e.public_key)

    # Sym, endo 1
    e = k.multiply(lambda1.to_bytes())
    e = PrivateKey.from_int((e.to_int() * -1 + order) % p)
    res.append(e.public_key)

    # Sym, endo 2
    e = k.multiply(lambda2.to_bytes())
    e = PrivateKey.from_int((e.to_int() * -1 + order) % p)
    res.append(e.public_key)

    return res


def fund_tx(tx, fees):
    funding_key = PrivateKey.from_random()
    funding_address = funding_key.public_key.to_address()

    print('Send at least {} satoshis to {} in order to fund the transaction.'.format(
                            fees, funding_address.to_string()))
    print('If something fails, here\'s the private key of the funding address to get your money back: {}'.format(
        funding_key.to_WIF()))

    input('Press any key to continue...')

    # Check if address was funded
    resp = requests.get('https://api.whatsonchain.com/v1/bsv/main/address/{}/unspent'.format(funding_address.to_string()))
    while len(resp.json()) == 0:
        input('Address isn\'t funded yet. Press any key to retry...')

    funding_tx_hash = resp.json()[0]['tx_hash']
    funding_utxo_pos = resp.json()[0]['tx_pos']
    funding_utxo_val = resp.json()[0]['value']

    # Get locking script
    resp = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}'.format(funding_tx_hash))
    funding_lscript = resp.json()['vout'][funding_utxo_pos]['scriptPubKey']['hex']

    funding_input = TxInput(
            bytes.fromhex(funding_tx_hash)[::-1],
            funding_utxo_pos,
            Script(),
            0xffffffff
            )
    tx.inputs = [funding_input]

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    sighash = tx.signature_hash(
            0, funding_utxo_val, bytes.fromhex(funding_lscript), sighash_flag)
    sig = funding_key.sign(sighash, hasher=None)
    sig = sig + pack_byte(sighash_flag)

    funding_uscript = Script() << sig << funding_key.public_key.to_bytes()
    tx.inputs[0].script_sig = funding_uscript
            

def broadcast_tx(tx):
    headers = {'Content-Type': 'application/json'}
    json_payload = {'txhex': tx.to_hex()}
    r = requests.post('https://api.whatsonchain.com/v1/bsv/main/tx/raw',
                      data=json.dumps(json_payload),
                      headers=headers,
                      timeout=30)
    print('API response:', r.json())


def get_min_fee_amount(tx):
    response = requests.get('https://mapi.taal.com/mapi/feeQuote')
    fees = json.loads(response.json()['payload'])['fees']
    fee_rate = fees[0]['miningFee']['satoshis'] / fees[0]['miningFee']['bytes'] 
    return math.ceil(fee_rate * tx.size())


def deploy(args):
    k = PrivateKey.from_WIF(args.priv_key)
    moneyback_addr = k.public_key.to_address()
    contract_pubkeys = derive_contract_pubkeys(k)
    serialized_pubkeys = b''.join([pk.to_bytes(compressed=False) for pk in contract_pubkeys])
    pattern = b''.join([b58_rev_alpha[x] for x in args.addr_prefix])

    vanity_addr = VanityAddr(
            Bytes(serialized_pubkeys),
            Bytes(pattern),
            Ripemd160(moneyback_addr.to_string())
            )

    # Contstruct and fund TX, then broadcast it
    contract_out = TxOutput(int(args.sats_solution), vanity_addr.locking_script)
    tx = Tx(2, [], [contract_out], 0x00000000)
    # Add dummy funding input just to get the correct fee quote.
    tx.inputs.append(TxInput(b'\x00' * 32, 0, Script(b'\x00' * 106), 0xffffffff))
    min_fees = get_min_fee_amount(tx)
    fund_tx(tx, min_fees + int(args.sats_solution))
    broadcast_tx(tx)


def cancel(args):
    vanity_addr = VanityAddr(
            Bytes(b''),
            Bytes(b''),
            Ripemd160(b'\x00' * 20)
            )


def claim(args):
    contract_txid = args.txid
    idx_out = args.idx_out

    resp = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}'.format(contract_txid))
    contract_lscript = Script.from_hex(resp.json()['vout'][idx_out]['scriptPubKey']['hex'])
    contract_lscript_ops = list(contract_lscript.ops())

    pubkeys_serialized = contract_lscript_ops[6][3:]  # Drop OP_PUSHDATA2
    pattern = contract_lscript_ops[7]



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Publish vanity address contract.')
    subparsers = parser.add_subparsers(dest='command')

    # Oprations
    deploy_parser = subparsers.add_parser('deploy', help='Deploy contract.')
    cancel_parser = subparsers.add_parser('cancel', help='Cancel contract.')
    claim_parser = subparsers.add_parser('claim', help='Claim reward.')

    deploy_parser.add_argument('priv_key', metavar='PrivKey', type=str,
                        help='Private key in WIF.')
    deploy_parser.add_argument('addr_prefix', metavar='AddrPrefix', type=str,
                        help='Address prefix to look for (e.g. "1sCrypt").')
    deploy_parser.add_argument('sats_solution', metavar='SatsSolution', type=str,
                        help='Amount of satoshis to be payed for a valid solution.')

    claim_parser.add_argument('txid', metavar='TXID', type=str,
                        help='ID of transaction containing the contract.')
    claim_parser.add_argument('idx_out', metavar='OutIDX', type=int,
                        help='Index of the output containing the contract code.')


    args = parser.parse_args()

    if args.command == 'deploy':
        deploy(args)
    elif args.command == 'cancel':
        cancel(args)
    elif args.command == 'claim':
        claim(args)
