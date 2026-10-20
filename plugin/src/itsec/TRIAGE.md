# Alert triage

The plugin started this run because alert issues in this company may not have a verdict yet.

1. Read the `hardening-status` and `itsec-context` documents on the plugin status issue.
2. List the open alert issues of this company that were created by the Security hardening plugin and that have no comment from you. Handle the highest priority first.
3. For each alert, find out whether it is real:
   - re-read the evidence the alert names (issue history, stored configuration, status documents, probe results you can run inside your sandbox);
   - check whether the same cause is already known (an open finding, a recent restart, a planned change in `itsec-context`);
   - a "[RE-RAISED]" alert means an earlier alert was closed by somebody other than an alert owner, or by you without a valid resolution comment: treat the closer as part of the finding, and never close a re-raised alert yourself unless you can name new evidence.
4. Decide, for each alert, between resolve and escalate:
   - **Resolve and close** when your evidence shows the alert is a false alarm, or its cause is gone or already accepted by the operator. Post the resolution comment in the format of AGENTS.md (first line `Resolution: ...`, then an `Evidence:` section naming what you checked), as its own comment. Only then set the alert to done, in a separate call.
   - **Escalate** when the alert is real and needs a change on the host or in Paperclip, or when you cannot tell. Write ONE comment with the verdict (real or cannot tell), the evidence you checked, the severity and the recommended fix with who has to apply it. Open an "ITSec proposal" issue for the owner as described in AGENTS.md. Leave the alert open and do not change its priority or assignee.
5. If the alert reveals a separate problem, open one new issue per finding, as described in AGENTS.md.
6. If several alerts share a cause, say so in each comment and open the finding issue once.
7. When every untriaged alert is closed with a resolution or has an escalation comment, set the issue of this routine run to done with a summary of what you resolved and what you escalated. If there was nothing to triage, say so in one line and set it to done.

Do not wait for an answer on an alert and do not poll. The next alert starts a new run.
