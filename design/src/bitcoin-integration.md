# Bitcoin Integration

Unlike Sui, Bitcoin can undergo chain reorganizations when forks arise and
eventually the network chooses the fork with the larger height as the winner.
Due to this many who interact in the bitcoin ecosystem wait for a number of
block confirmations before recognizing that the transactions in a block are
considered final. The industry standard seems to sit around waiting for 6
confirmations before treating a block as final. As such we'll also use a
minimum of 6-10 confirmations before our system recognizes a block as final.

We'll have a shared object used to track the latest bitcoin blocks. As new
bitcoin blocks are mined, the committee will form a cert to confirm a block or
set of blocks. Once a block has enough confirmations it'll graduate to become
the new finalized chain head for the purposes of determining if a transaction
has settled and is finalized on btc.

Each time a new block is finalized, the quorum will process the block and
either mint sBTC for each new UTXO or close out any previously pending
withdrawals on the sui side.

We'll need a shared object to maintain the set of UTXOs and/or public keys
(addresses) that the committee is managing. This will act as both an accounting
mechanism as well as a nonce/replay protection mechanism. As UTXOs are
deposited, entries will be added, and as UTXOs are withdrawn (spent), entries
will be removed, all after the requisite number of confirmations.

### Alternative
Alternatively we could implement btc block verification inside of move and have
them all verified inside of move (block headers). To do this we'd need to
expose a sha256 hash function to be used in move.

We could also just have the committee act as an oracle and instead have users
need to drive the formation of a cert to have btc collateral minted on the sui
side.
