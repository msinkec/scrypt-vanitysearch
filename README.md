# scrypt-vanitysearch

Deployment code for a contract, that allows for trustless generation of Bitcoin vanity addresses. 

[VanitySearch](https://github.com/JeanLucPons/VanitySearch) optimizations (symmetry and endomorphism) are supported. The contract itself is written in [sCrypt](https://scrypt.io).


## Usage

### Deploy contract
Generate an arbitrary private key `k`, that you will use to assemble the final private key of your vanity address.

Then run:

```
./vanity.py deploy <private key k (WIF)> <prefix> <award sats>

# Example:
# ./vanity.py deploy L2yiMfGo2wLaNmF3wTTBLbrzM39LonTVqNg7nEutbBvRkYgTYB1c 1miha 100000
```

### Cancel contract
If you want to cancel your contract, then run the following command:

```
./vanity.py cancel <contract txid> <index of contract output> <private key k (WIF)> <payment destination address>
```

### Info on deployed contract
The following command prints info about a deployed contract:

```
./vanity.py info <contract txid> <index of contract output>
```

### Claim reward
Once you find a valid partial private key `x` with VanitySearch, you can claim your reward:

```
./vanity.py claim <contract txid> <index of contract output> <private key x (WIF)> <reward destination address>
```

### Assemble final key pair
When someone claims your contract, you can assemble the final key pair like so:

```
./vanity.py assemble <spending contract txid> <index of contract unlocking input> <private key k (WIF)>
```

