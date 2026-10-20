# Alert triage

The plugin started this run because alert issues in this company may not have a verdict yet.

1. Read the `hardening-status` and `itsec-context` documents on the plugin status issue.
2. List the open alert issues of this company that were created by the Security hardening plugin and that have no comment from you. Handle the highest priority first.
3. For each alert, find out whether it is real:
   - re-read the evidence the alert names (issue history, stored configuration, status documents, probe results you can run inside your sandbox);
   - check whether the same cause is already known (an open finding, a recent restart, a planned change in `itsec-context`);
   - a "[RE-RAISED]" alert means somebody other than an alert owner closed an earlier alert: treat the closer as part of the finding.
4. Write ONE comment on the alert issue with: verdict (real, false alarm, or cannot tell), the evidence you checked, severity, and the recommended fix with who has to apply it. Do not change the alert's status, priority or assignee. Do not close it.
5. If the alert reveals a separate problem, open one new issue per finding, as described in AGENTS.md.
6. If several alerts share a cause, say so in each comment and open the finding issue once.
7. When all untriaged alerts have a comment, set the issue of this routine run to done with a summary of what you triaged. If there was nothing to triage, say so in one line and set it to done.

Do not wait for an answer on an alert and do not poll. The next alert starts a new run.
