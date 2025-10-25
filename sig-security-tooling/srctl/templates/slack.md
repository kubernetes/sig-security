_Use this slack message template for publicly disclosing security vulnerabilities on slack._

_This message should be posted to the `#announcements` channel, which requires special permissions._

---

The Security Response Committee has posted a security advisory for $COMPONENT that $SUMMARY. This
issue has been rated **$SEVERITY** and assigned **$CVE**. Please see $ISSUE for more details.

---

_Example_

The Security Response Committee has posted a security advisory for the kube-apiserver that could
allow node updates to bypass a Validating Admission Webhook. This issue has been rated **Medium**
and assigned **CVE-2021-25735**. Please see https://github.com/kubernetes/kubernetes/issues/100096
for more details.