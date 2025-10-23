# Bitcoin Integration

Unlike Sui, Bitcoin can undergo chain reorganizations when forks arise and
eventually the network chooses the fork with the larger height as the winner.
Due to this many who interact in the bitcoin ecosystem wait for a number of
block confirmations before recognizing that the transactions in a block are
considered final. The industry standard seems to sit around waiting for 6
confirmations before treating a block as final. As such we'll also use a
minimum of 6-10 confirmations before our system recognizes a block as final.

Hashi will have a UTXO pool object to maintain the set of UTXOs that the
committee is managing. This will act as both an accounting mechanism as well as
a nonce/replay protection mechanism. As UTXOs are deposited, entries will be
added, and as UTXOs are withdrawn (spent), entries will be removed, all after
the requisite number of confirmations.
