# Reconfiguration

Reconfiguration will be required happen immediately upon the epoch change on
Sui occurring. We can have the hashi service monitor the expected time at which
the epoch will close to determine if new operations should be scheduled so that
there are no outstanding operations that need to complete when the epoch change
happens and hashi can immediately begin reconfig.

The exact details of committee reconfiguration are still TBD, but one possible
design would be:
- immediately post sui epoch change we inspect the new sui committee and
  determine the new committee for the bridge. This will require effort from the
  move team to add the ability to inspect the system state using a non-mutable
  reference.

- existing committee begins the process of handing off to the new committee

Reconfiguration will likely always happen while the committee has other/on
going operations in flight. We'll need to figure out if we should complete
pending operations or if reconfiguration should preempt those operations which
can resume once a new committee has been installed.
