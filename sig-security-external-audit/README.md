# SIG Security External Audit Subproject

## Overview

The SIG Security External Audit subproject (subproject, henceforth) is responsible for coordinating regular, 
comprehensive, third-party security audits.
The subproject publishes the deliverables of the audit after abiding to the 
[Security Release Process](https://github.com/kubernetes/committee-security-response/blob/main/security-release-process.md) and 
[embargo policy](https://github.com/kubernetes/committee-security-response/blob/main/private-distributors-list.md#embargo-policy).

  
  - [Initial steps](#initial-steps)
  - [Request for Proposal (RFP)](#rfp)
    - [Security Audit Scope](#security-audit-scope)
    - [Vendor and Community Questions](#vendor-and-community-questions)
  - [Review of Proposals](#review-of-proposals)
  - [Vendor Selection](#vendor-selection)
  - [SRC Review](#src-review)
  - [Deliverables](#deliverables)
  - [Publish Findings](#publish-findings)

## Initial steps

Notify the CNCF and Kubernetes Steering Committee that the External Audit subproject is in the initial phase of an external audit. Ask the Kubernetes Steering Committee through the [#steering-committee Slack channel](https://kubernetes.slack.com/archives/CPNFRNLTS) to create a ticket with the [CNCF Service Desk](http://servicedesk.cncf.io/). Only Steering Committee members, SIG ContribEx leads, SIG Release leads, and SIG K8s-Infra leads can create service desk tickets with the CNCF for Kubernetes.

Create an umbrella issue under https://github.com/kubernetes/sig-security to track tasks and progress of the external audit. e.g. https://github.com/kubernetes/sig-security/issues/104

## RFP

The subproject produces a RFP for a third-party, comprehensive security audit. The subproject publishes the RFP in the 
`sig-security` folder in the `kubernetes/community` repository. The subproject defines the scope, schedule, 
methodology, selection criteria, and deliverables in the RFP.

Previous RFPs:
  - [2019](https://github.com/kubernetes/sig-security/blob/main/sig-security-external-audit/security-audit-2019/RFP.md)
  - [2021](https://github.com/kubernetes/sig-security/blob/main/sig-security-external-audit/security-audit-2021/RFP.md)

As efforts begin for the year's security audit, create a tracking issue for the security audit in 
`kubernetes/community` with the `/sig security` label.

### Security Audit Scope

The scope of an audit is the most recent release at commencement of audit of the core 
[Kubernetes project](https://github.com/kubernetes/kubernetes) and certain other code maintained by 
[Kubernetes SIGs](https://github.com/kubernetes-sigs/).

Core Kubernetes components remain as focus areas of regular audits. Additional focus areas are finalized by the 
subproject.

### Vendor and Community Questions

Potential vendors and the community can submit questions regarding the RFP through a Google form. The Google form is 
linked in the RFP. 
[Example from the 2021 audit](https://docs.google.com/forms/d/e/1FAIpQLScjApMDAJ5o5pIBFKpJ3mUhdY9w5s9VYd_TffcMSvYH_O7-og/viewform).

The subproject answers questions publicly on the RFP with pull requests to update the RFP. 
[Example from the 2021 audit](https://github.com/kubernetes/community/pull/5813).

The question period is typically open between the RFP's opening date and closing date.

## Review of Proposals

Proposals are reviewed by the subproject proposal reviewers after the RFP closing date. An understanding of security audits is required to be a proposal reviewer.

All proposal reviewers must agree to abide by the 
**[Security Release Process](https://github.com/kubernetes/committee-security-response/blob/main/security-release-process.md)**, 
**[embargo policy](https://github.com/kubernetes/committee-security-response/blob/main/private-distributors-list.md#embargo-policy)**, 
and have no [conflict of interest](#conflict-of-interest) the tracking issue. 
This is done by placing a comment on the issue associated with the security audit. 
e.g. `I agree to abide by the guidelines set forth in the Security Release Process, specifically the embargo on CVE 
communications and have no conflict of interest`

Proposal reviewers are members of a private Google group and private Slack channel to exchange sensitive, confidential information and to share artifacts.

### Conflict of Interest

There is a possibility of a conflict of interest between a proposal reviewer and a vendor. Proposal reviewers should not have a conflict of interest. Examples of conflict of interest:
  - Proposal reviewer is employed by a vendor who submitted a proposal
  - Proposal reviewer has financial interest directly tied to the audit

Should a conflict arise during the proposal review, reviewers should notify the subproject owner and SIG Security chairs when they become aware of the conflict.

> The _Conflict of Interest_ section is inspired by the 
[CNCF Security TAG security reviewer process](https://github.com/cncf/tag-security/blob/main/assessments/guide/security-reviewer.md#conflict-of-interest).

## Vendor Selection

On the vendor selection date, the subproject will publish a the selected vendor in the 'sig-security' folder in the `kubernetes/community` repository. 
[Example from the 2019 audit](https://github.com/kubernetes/sig-security/blob/main/sig-security-external-audit/security-audit-2019/RFP_Decision.md).


## SRC review

Send findings to the SRC for review and discussion.

## Deliverables

The deliverables of the audit are defined in the RFP e.g. findings report, threat model, white paper, audited reference architecture spec (with yaml manifests) and published in the 'sig-security' folder in the `kubernetes/community` repository. 
[Example from the 2019 audit](https://github.com/kubernetes/sig-security/tree/main/sig-security-external-audit/security-audit-2019/findings).

**All information gathered and deliverables created as a part of the audit must not be shared outside the vendor or the subproject without the explicit consent of the subproject and SIG Security chairs.**

## Publish findings

Coordinate with the vendor and CNCF to publish a blog post to announce the findings.
The blog post may serve as the publication of the audit findings. 

Previous blog posts:
[2023 New Kubernetes security audit complete and open sourced](https://www.cncf.io/blog/2023/04/19/new-kubernetes-security-audit-complete-and-open-sourced/)
[2019 Open sourcing the Kubernetes security audit](https://www.cncf.io/blog/2019/08/06/open-sourcing-the-kubernetes-security-audit/)

Just before the blog publication, merge the audit findings in https://github.com/kubernetes/sig-security/tree/main/sig-security-external-audit. 

The blog may have a link to the findings in https://github.com/kubernetes/sig-security/tree/main/sig-security-external-audit that will have to be live before the blog is published.