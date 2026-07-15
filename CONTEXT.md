# StrfryGUI

StrfryGUI manages a strfry relay, including moderation decisions and their effects on relay content.

## Language

**Moderation report**:
A relay user's report about an event or pubkey that requires a moderation decision. It is resolved when that decision is recorded, independently of follow-up enforcement or Event purge outcomes.

**Moderation decision**:
An operator's recorded disposition of a Moderation report, reported event, or Ban. Each decision and its audit history are one indivisible record of change.

**Ban**:
A durable moderation decision that a pubkey may not write future events to the relay. A Ban can exist while its enforcement or removal of existing events is incomplete, and repeated decisions preserve its original provenance.

**Unban**:
A moderation decision that removes a Ban from the active set. It is recorded in the audit history and does not restore events removed by an Event purge.

**Ban enforcement**:
The application of the Write-policy projection to the relay. Enforcement may be pending when publication fails and must converge with the recorded Bans.

**Write-policy projection**:
The complete set of recorded Bans prepared for relay enforcement. Its publication state belongs to the set as a whole, not to any individual Ban.

**Event purge**:
A durable, retryable moderation task to remove existing relay events matching a target. An Event purge is distinct from a Ban and remains visible until its outcome is known.
_Avoid_: Ban
