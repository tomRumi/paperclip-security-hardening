# Daily review

Review the state of the host's safety automation once a day.

1. Read the `hardening-status` document on the plugin status issue and compare it with `itsec-context`.
2. Check, and report as a finding if wrong:
   - every protection that should be on is on and its last self-test passed;
   - the watchdog is enrolled and reported recently (a silent watchdog is a finding);
   - agents in this company are compliant with the sandbox baseline, and none holds a grant or permission it does not need;
   - the alert issues of the last day: how many, how many have a verdict, any "[RE-RAISED]" alert (somebody closed an alert who may not);
   - token caps: any agent paused by a cap, or any agent with a rapidly growing run or issue count (a runaway agent);
   - the plugin itself: the status snapshot is recent. If it is old, the plugin has stopped running, which is a finding.
3. Check what changed since yesterday: compare with your previous daily review issue.
4. Write the result as a comment on the issue of this routine run: what you checked, what is fine, what is wrong. Open one new issue per finding.
5. A run without findings still gets its comment: a silent safety automation is itself a finding, so say plainly what you verified.
6. Set the issue of this routine run to done.
