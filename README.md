# sp-faucet

## Setup

1. Bitcoin Core
```
#Example configuration file
daemon=1

[signet]
txindex=1
listen=1
zmqpubrawblock=tcp://127.0.0.1:29000
zmqpubrawtx=tcp://127.0.0.1:29000
whitelist=download@127.0.0.1
blockfilterindex=1
wallet=default
```

2. Electrs (build this [branch](https://github.com/Sosthene00/electrs/tree/fix_dependencies))

3. configuration file example (`.config` in the root dir)
```
core_url="127.0.0.1:38332"
ws_url="127.0.0.1:8090"
wallet_name="default"
network="signet"
electrum_url="tcp://localhost:60601"
zmq_url="tcp://127.0.0.1:29100"
```

## Description of current workflow (to be modified)

### Websocket

A loop is listening for incoming ws connection and spawn a new thread for each connected peer. A list of currently connected peer is kept in the PEERMAP static variable.

### zmq

The faucet subscribes to the Core zmq `rawtx` and `hashblock`. When a `rawtx` message is received, it looks up the inputs via Core rpc and computes the tweak_data. It then sends the raw transaction along with the tweak to all connected peers.

### wallet

Wallet is saved to disk in the very rudimentary form of a file containing the whole wallet in json. 

### FaucetRequest

A `FaucetMessage` contains a silent payment address and an amount. Amount is capped between 100,000 and 1,000,000 sats for now (arbitrary). If we have at least twice the amount asked in our wallet, we directly make a transaction to pay the request. If not, we first pull 4 times the max amount from Core wallet. As long as Core can't directly send to sp address, we will generate a key on the fly to send to, and then immediately spend it to satisfy the request, the remainder going to our wallet. 

### FaucetResponse

If the sending is successful, the faucet will answer with a `FaucetResponse` message that contains the paying transaction along with the `tweak_data`. Client can then easily compute its own address and check that the transaction is okay. 
