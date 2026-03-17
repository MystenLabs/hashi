# Reconfiguration

One of the most important parts of the hashi protocol is reconfiguration. This
is because one of the key parts of reconfiguration is the old committee
sharing key shares of the MPC key with the new committee.

The hashi service will monitor the Sui epoch change and will immediately kick
off hashi reconfig once Sui's epoch change completes. During hashi's reconfig,
in progress operations (e.g. processing of withdrawals) will be paused and will
be resumed and processed by the new committee upon the completion of
reconfiguration.

TODO add detailed flow diagrams
