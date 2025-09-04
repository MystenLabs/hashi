# Limiter

TBD Design for limiting in/out flows for the system.

Some high level learnings from the existing native eth bridge:
- limits should be denominated in the currency itself, and not in the converted USD value.
- We need to have a queue for withdrawals where a user can, up to a point, opt to get out of the queue.
- we need a way to handle amounts that are >> the limits (time delay vs forcing them to break it up).
