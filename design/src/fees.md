# Fees

Hashi will have configurable Deposit and Withdraw fees as a way to pay for the
protocol and as a means of deterring DoS attacks.

**Deposits**: When a deposit request is registered, the user will need to pay a
fee in `SUI`. Initially this will be `0 SUI`.

**Withdraws**: When a withdraw request is registered, the user will need to pay
a fee in `SUI`. Initially this will be `0 SUI`. In addition to this, there will
be a fee in `BTC`, taken out of the amount the user is trying to withdraw, in
order to pay for the Bitcoin transaction fee. This value will be set at a level
to ensure that Bitcoin transactions that hashi broadcast are quickly picked up
by miners to be mined.

If a Bitcoin transaction fails to be included in a block in a reasonable period
of time it may require that the protocol do a governance action to up the
Bitcoin fee. The protocol will never attempt to rebuild and sign a transaction
with a higher fee to replace a transaction waiting in the mempool. Instead CPFP
(Child Pays for Parent) will expected to be used, either by the recipient of a
withdrawal, or hashi trying to use a UTXO that went back into the pool.
