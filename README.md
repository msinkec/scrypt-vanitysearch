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

