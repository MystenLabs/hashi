# Governance Actions

Every governance action will have their own configurable stake thresholds for a particular proposal to pass.

**Halting the system**
We'll have a `HALT` governance action which will halt all processing of
Deposits and Withdrawals and a `RESUME` governance action which will resume
processing of Deposits and Withdrawals. The threshold for stoping the system
will be rather low (2-3%) while the threshold for resuming will be large (67%).

**Cancel Withdraw**
If its found that a withdraw is problematic before its begun to be processed
(e.g. a hacker trying to move a large amount of funds). Then we'll be able to
pause system and then have a manual action to confiscate the withdraw request
till further review.
