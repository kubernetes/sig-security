**Open Source Technology Improvement Fund, Inc                                     **

*https://ostif.org*

**Request for Proposals**


    **Purpose**


    This RFP form will help communicate resources needed and security goals for the audit of multiple K8s subprojects and components. Additionally, this form defines the expectations of OSTIF and the criteria used to evaluate and select proposals.

**About Us **


    Open Source Technology Improvement Fund, Inc (OSTIF) was founded in 2015 with the mission of connecting open-source projects with much needed resources and logistical support. Since then, over 10,000 hours of audit work for critical open-source software has been coordinated. This security work has resulted in the patching of hundreds of security bugs, impacting billions of users globally. We have partnered with more than 50 organizations to facilitate audits for a variety of open-source  projects, such as OpenSSL, OpenVPN, and Unbound DNS. 


    As a 501(c)3 nonprofit organization, OSTIF has remained devoted to strengthening the Internet by improving the security of free and open software. We are committed to helping our partners and clients get the resources they need to maintain secure and reliable software. 

    Since 2022, the CNCF have been working with OSTIF to conduct security audits for incubating and graduated CNCF projects. For more background on CNCF’s partnership with OSTIF and security audits, checkout blogs from [2022](https://www.cncf.io/blog/2022/08/08/improving-cncf-security-posture-with-independent-security-audits/) and [2023](https://www.cncf.io/blog/2023/03/13/an-overview-of-the-cncf-and-ostif-impact-report-for-the-second-half-of-2022-and-early-2023/)

**Expectations and RFP Selection Criteria**

OSTIF considers a diverse range of criteria when selecting a proposal for a project. This matrix outlines the main selection criteria:


<table>
  <tr>
   <td><strong>Criteria</strong>
   </td>
   <td><strong>Description</strong>
   </td>
   <td><strong>Weight</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Openness</strong>
   </td>
   <td>Is the audit team willing to work fully transparently? Can their work be published for the public to review? Can their bids be public if required? Have they worked with open source software before?
   </td>
   <td><strong>PASS/FAIL</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Scope</strong>
   </td>
   <td>Is the proposed scope reasonable and well defined? Does it cover enough to make a meaningful impact, without waste? (covering items already in the CI pipeline, etc)
   </td>
   <td><strong>20 points</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Expertise</strong>
   </td>
   <td>Who is working on the project? Do the auditors have specific experience reviewing this type of software? Do they have published work in this area?
   </td>
   <td><strong>30 points</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Cost</strong>
   </td>
   <td>Are the proposed rates competitive with proposals of similar scope?
   </td>
   <td><strong>30 points</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Past Performance</strong>
   </td>
   <td>Have we worked with this team before? Were projects completed on schedule? Were the results in line with expectations?
   </td>
   <td><strong>10 points</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Documentation Quality</strong>
   </td>
   <td>All OSTIF work is done in public. Audit document quality is crucially important because the public is reviewing the overall quality of our published work continuously.
   </td>
   <td><strong>10 points</strong>
   </td>
  </tr>
  <tr>
   <td>
   </td>
   <td><strong>Total possible score**</strong>
   </td>
   <td><strong>100 points</strong>
   </td>
  </tr>
</table>


**In the unlikely event of a tie, diversity and inclusion of the audit team is considered for race, gender, and ethnic background to help promote a healthy and diverse professional environment for all.


<table>
  <tr>
   <td><strong>Proposed Project: K8s</strong>
   </td>
   <td><strong>Maximum Budget: TBD</strong>
   </td>
  </tr>
  <tr>
   <td>Github: Many - See below
<p style="text-align: center">
Website: <a href="https://kubernetes.io/">https://kubernetes.io/</a>
   </td>
   <td><em>Note: Budget is strongly considered as a criterion for project selection. The maximum budget is to give firms guidance on the relative expectations of the client.</em>
   </td>
  </tr>
</table>



<table>
  <tr>
   <td><strong>Language(s)</strong>
<p style="text-align: center">
Go
   </td>
   <td><strong>License(s)</strong>
<p style="text-align: center">
Apache 2.0
   </td>
  </tr>
</table>


For more information, see [OSTIF's Open Source Security Audit Minimum Standards and Expectations](https://docs.google.com/document/d/19ug1JSEFs_0-Tj2B4Co7rE7bMkZGDL_45VDKnBD0bNc)

**Overall Project Description**

Kubernetes, also known as K8s, is an open source system for automating deployment, scaling, and management of containerized applications. Kubernetes is the premiere platform for open source containerized computing and a cornerstone of the global cloud computing industry. This security review focuses on specific components and subprojects that were out-of-scope in previous K8s audits, giving crucial insight into the security and health of these projects.

Below are the components identified by the Kubernetes community as both needing additional security scrutiny and whose maintainers are open to enthusiastically participating in this project.

Because it is understood that there is far too much code to cover inside of the budget provided, these projects are prioritized both the perceived criticality of the component by the community, and the information level of the documentation provided. It should also be carefully noted that auditors will have the flexibility to investigate hunches and seek out issues in other components if they so choose. The “high priority” items in the list must be reviewed in full, while the components in the table marked “lower priority” should be completed ad-hoc on a best effort basis.

Note that a few items in this document differ in priority from the [2024 Kubernetes Audit Scope document](https://docs.google.com/spreadsheets/d/1b_OrTHzLcPisShcera9eKtycKZORvW1z8Hm2If4NCF4). These changes were made due to continuous feedback from the Kubernetes security community and the priorities listed in this document should be considered the most up-to-date.

Additional note: Some projects have little to no information about where the feature lives nor links to documentation. It will be the responsibility of the researchers to discover what these components do, where the code lives in the codebase, and investigate.

High priority components are listed below.

**Component / Subproject: Cluster API \
**(Row 2 on the K8s Security Audit Scope Table ) \
Estimated 209K LOC / Complexity High

**References \
**Link to project: [https://github.com/kubernetes-sigs/cluster-api](https://github.com/kubernetes-sigs/cluster-api)** \
**Docs: [https://cluster-api.sigs.k8s.io/](https://cluster-api.sigs.k8s.io/)

**Component / Subproject: Pod Security Admission  \
**(Row 3 [on the K8s Security Audit Scope Table](https://docs.google.com/spreadsheets/d/1b_OrTHzLcPisShcera9eKtycKZORvW1z8Hm2If4NCF4) ) \
Estimated 10K LOC / Complexity Medium** **

**References \
**Docs: [https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/2579-psp-replacement/README.md](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/2579-psp-replacement/README.md)

 \
**Component / Subproject: Multiple Windows Components**  \
(Row 4 [on the K8s Security Audit Scope Table](https://docs.google.com/spreadsheets/d/1b_OrTHzLcPisShcera9eKtycKZORvW1z8Hm2If4NCF4) )

Estimated LOC Unknown / Complexity High (interacting with closed source for debugging)

The Kubernetes Community has requested multiple Windows components for review, this includes straightforward blocks of code within the Kubernetes project, as well as documentation that refers to specific features for Kubernetes on Windows. 

In the case of references to blocks of code, the testing coverage (static and dynamic) should be evaluated, and tests should be updated where appropriate with a focus on meaningful security findings with a low rate of false positives that the community must sift through. Additionally, the attack surface of the subproject should be considered and manual review conducted for high risk code blocks. If code blocks are found that would benefit from fuzz testing that are not currently covered in ossfuzz, harnesses should be built and the coverage improvements should be documented for the final report.

In the case of references to features, the appropriate blocks of code must be located, and the same level of scrutiny should be applied to investigate the code for potential flaws.

In the case of references to documentation, checks should be made to ensure that users should be able to create secure implementations by default, and that non default settings should be documented for any security risks that may be present.


# **Components with Higher Priority**


### **Component: Konnectivity Client**

Estimated LOC 2K + other PRs / Complexity High


### **Component: Shared pubic cloud library**

Estimated LOC 15K + other PRs / Complexity Low


### **Component: credential provider plugin**

Estimated LOC 2K + other PRs / Complexity Medium (handles security secrets / permissions)


### **Component: Image builder**

Estimated LOC 11K + other PRs (JSON/YAML) / Complexity Low


### **Component: CEL Admission Control / ValidatingAdmissionPolicy**

Estimated LOC 23K + other PRs / Complexity High (handles security secrets / permissions)

**Component: Ephemeral Containers**

Pull requests available in the [K8s Security Audit Scope Table](https://docs.google.com/spreadsheets/d/1b_OrTHzLcPisShcera9eKtycKZORvW1z8Hm2If4NCF4)

**Component: cgroups v2**

Related Pull Request: [https://github.com/kubernetes/kubernetes/pull/85218](https://github.com/kubernetes/kubernetes/pull/85218)

**Component: Windows Privileged Containers and Host Networking Mode**

Pull requests available in the [K8s Security Audit Scope Table](https://docs.google.com/spreadsheets/d/1b_OrTHzLcPisShcera9eKtycKZORvW1z8Hm2If4NCF4)

**Component: Seccomp by default** \
Complexity to be assessed by auditors / No information available

 \
**Component: Node Topology Manager** \
Complexity to be assessed by auditors / No information available

 \
**Component: Support 3rd party device monitoring plugins**

Complexity to be assessed by auditors / No information available

**Component: AppArmor Support**

Complexity to be assessed by auditors / No information available

**Component: Local Ephemeral Storage Capacity Isolation** \
Related Pull Request: [https://github.com/kubernetes/kubernetes/pull/111513](https://github.com/kubernetes/kubernetes/pull/111513)

**Component: Cleaning Up IPTables Chain Ownership**

Complexity to be assessed by auditors / No information available

**Component: CRD Validation Expression Language**

Complexity to be assessed by auditors / No information available


# **Components with Lower Priority**

Below is a sanitized and sorted table for all of the remaining components in this engagement. ***Lower Priority components/features should be assessed on a best effort basis after all of the above features have been evaluated.*** If the researchers do not get to some of the components in this section of the scope, it should be carefully noted which components were not covered by this review, which will be crucial for follow-up research at a later time.

 

**Disclaimer: Components and Features with No Information**

Some components were submitted by the community with little to no information about the functionality or code related to them. For all of the following projects, features were brought in by the community in an ad-hoc fashion and less overall information was provided about their nature and where they live in the codebase. Researchers will need to refer to the PRs if provided, and the Kubernetes / subproject documentation to drill down and locate the code, understand the design, and make security assessments. 


<table>
  <tr>
   <td><strong>Full List of Additional Components with Lower Priority</strong>
   </td>
   <td><strong>Derived From the <a href="https://docs.google.com/spreadsheets/d/1b_OrTHzLcPisShcera9eKtycKZORvW1z8Hm2If4NCF4">Original List Here</a></strong>
   </td>
  </tr>
  <tr>
   <td>CSI Migration Core
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/69830">https://github.com/kubernetes/kubernetes/pull/69830</a>
   </td>
  </tr>
  <tr>
   <td>AWS EBS in-tree to CSI driver migration
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/115838">https://github.com/kubernetes/kubernetes/pull/115838</a>
   </td>
  </tr>
  <tr>
   <td>GCE PD in-tree to CSI driver migration
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/111301">https://github.com/kubernetes/kubernetes/pull/111301</a>
   </td>
  </tr>
  <tr>
   <td>vSphere in-tree to CSI driver migration
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/113336">https://github.com/kubernetes/kubernetes/pull/113336</a>
   </td>
  </tr>
  <tr>
   <td>Azure file in-tree to CSI driver migration
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/113160">https://github.com/kubernetes/kubernetes/pull/113160</a>
   </td>
  </tr>
  <tr>
   <td>TimeZone support in CronJob
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Stay on supported Go versions
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Field status.hostIPs added for Pod
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Metric cardinality enforcement
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Move cgroup v1 support into maintenance mode
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>kOps
   </td>
   <td><a href="https://github.com/kubernetes/kops">https://github.com/kubernetes/kops</a>
   </td>
  </tr>
  <tr>
   <td>CSI Inline Volumes (CSI Ephemeral Volumes)
   </td>
   <td>https://github.com/kubernetes/kubernetes/pull/74086
<p>
https://github.com/kubernetes/kubernetes/pull/81960
<p>
https://github.com/kubernetes/kubernetes/pull/82004
<p>
https://github.com/kubernetes/kubernetes/pull/111258
   </td>
  </tr>
  <tr>
   <td>Scheduler Component Config API
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/110534">https://github.com/kubernetes/kubernetes/pull/110534</a>
   </td>
  </tr>
  <tr>
   <td>Allow DaemonSets to MaxSurge to improve workload availability (like Deployments)
   </td>
   <td>https://github.com/kubernetes/kubernetes/pull/96375
<p>
https://github.com/kubernetes/kubernetes/pull/96441
   </td>
  </tr>
  <tr>
   <td>Network Policy to support Port Ranges
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/97058">https://github.com/kubernetes/kubernetes/pull/97058</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/110868">https://github.com/kubernetes/kubernetes/pull/110868</a>
   </td>
  </tr>
  <tr>
   <td>minReadySeconds for Statefulsets
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/100842">https://github.com/kubernetes/kubernetes/pull/100842</a>
<p>
https://github.com/kubernetes/kubernetes/pull/104045
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/110896">https://github.com/kubernetes/kubernetes/pull/110896</a>
   </td>
  </tr>
  <tr>
   <td>Identify Pod's OS during API Server admission (Identify Windows pods at API admission level authoritatively)
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/105919">https://github.com/kubernetes/kubernetes/pull/104693</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/105919">https://github.com/kubernetes/kubernetes/pull/104613</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/105919">https://github.com/kubernetes/kubernetes/pull/105292</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/105919">https://github.com/kubernetes/kubernetes/pull/107859</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/105919">https://github.com/kubernetes/kubernetes/pull/105919</a>
   </td>
  </tr>
  <tr>
   <td>Provide fsgroup of pod to CSI driver on mount
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/113225">https://github.com/kubernetes/kubernetes/pull/103244</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113225">https://github.com/kubernetes/kubernetes/pull/106330</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113225">https://github.com/kubernetes/kubernetes/pull/113225</a>
   </td>
  </tr>
  <tr>
   <td>Job tracking without lingering Pods
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/113510">https://github.com/kubernetes/kubernetes/pull/98238</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113510">https://github.com/kubernetes/kubernetes/pull/105197</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113510">https://github.com/kubernetes/kubernetes/pull/105687</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113510">https://github.com/kubernetes/kubernetes/pull/113176</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113510">https://github.com/kubernetes/kubernetes/pull/113478</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113510">https://github.com/kubernetes/kubernetes/pull/113510</a>
   </td>
  </tr>
  <tr>
   <td>Service Internal Traffic Policy
   </td>
   <td>https://github.com/kubernetes/kubernetes/pull/96600
<p>
https://github.com/kubernetes/kubernetes/pull/103409
   </td>
  </tr>
  <tr>
   <td>Tracking Terminating Endpoints in the EndpointSlice API
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/92968">https://github.com/kubernetes/kubernetes/pull/92968</a>
   </td>
  </tr>
  <tr>
   <td>Kubelet Credential Provider
   </td>
   <td>https://github.com/kubernetes/test-infra/pull/27724
<p>
https://github.com/kubernetes/kubernetes/pull/111616
<p>
https://github.com/kubernetes/kubernetes/pull/111495
   </td>
  </tr>
  <tr>
   <td>Support of mixed protocols in same Service definition with type=LoadBalancer
   </td>
   <td>https://github.com/kubernetes/kubernetes/pull/75831
<p>
https://github.com/kubernetes/kubernetes/pull/94028
<p>
https://github.com/kubernetes/kubernetes/pull/112895
   </td>
  </tr>
  <tr>
   <td>Reserve Service IP Ranges For Dynamic and Static IP Allocation
   </td>
   <td>https://github.com/kubernetes/kubernetes/pull/106792
<p>
https://github.com/kubernetes/kubernetes/pull/112163
   </td>
  </tr>
  <tr>
   <td>Add CPU Manager to kubelet
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/113018">https://github.com/kubernetes/kubernetes/pull/112855</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/113018">https://github.com/kubernetes/kubernetes/pull/113018</a>
   </td>
  </tr>
  <tr>
   <td>Add Device Manager to kubelet
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/112980">https://github.com/kubernetes/kubernetes/pull/112980</a>
   </td>
  </tr>
  <tr>
   <td>Mutable scheduling directives for suspended Jobs
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Downward API support for hugepages
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>kubectl default container
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Expose Pod Resource Request Metrics
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Server Side Unknown Field Validation
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Add gRPC probe to Pod.Spec.Container.{Liveness,Readiness,Startup}Probe
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Liveness Probe Grace Period
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>OpenAPI v3
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>kubectl events
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Retroactive default StorageClass assignment
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Non-graceful node shutdown
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Self subject review API
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Proxy Terminating Endpoints
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Expanded DNS configuration
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Minimize iptables-restore input size
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Kubelet endpoint for device assignment observation details
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Extend kubelet pod resource assignment endpoint to return allocatable resources
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Move EndpointSlice Reconciler into Staging
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Remove transient node predicates from KCCM's service controller
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Reserve Nodeport Ranges For Dynamic And Static Port Allocation
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Priority and Fairness for API Server Requests
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Support paged LIST queries from the Kubernetes API
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>ReadWriteOncePod PersistentVolume Access Mode
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Kubernetes Component Health SLIs
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>NodeExpandSecret for CSI Driver
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Track Ready Pods in Job status
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Kubelet Resource Metrics Endpoint
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Container Resource based Pod Autoscaling
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Remove transient node predicates from KCCM's service controller
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Go workspaces for kubernetes/kubernetes repo
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Reduction of Secret-based Service Account Tokens
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Pod Scheduling Readiness
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Min domains in PodTopologySpread
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Prevent unauthorized volume mode conversion during volume restore
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>API Server tracing
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Cloud Dual-Stack --node-ip Handling
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Robust VolumeManager reconstruction after kubelet restart
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Interactive(-i) flag to kubectl delete for user confirmation
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Metric cardinality enforcement
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Aggregated Discovery
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>PersistentVolume last phase transition time
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Kube-proxy improved ingress connectivity reliability
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Add CDI devices to device plugin API
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>PodHealthyPolicy for PodDisruptionBudget
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Retriable and non-retriable Pod failures for Jobs
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Elastic Indexed Jobs
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Allow StatefulSet to control start replica ordinal numbering
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Random Pod selection on ReplicaSet downscaling
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>CEL-based admission webhook match conditions
   </td>
   <td><a href="https://github.com/kubernetes/kubernetes/pull/119380">https://github.com/kubernetes/kubernetes/pull/116261</a>
<p>
<a href="https://github.com/kubernetes/kubernetes/pull/119380">https://github.com/kubernetes/kubernetes/pull/119380</a>
   </td>
  </tr>
  <tr>
   <td>kOps
   </td>
   <td>
   </td>
  </tr>
</table>


**Additional References**

Pod Security Policy Replacement Project Docs: \
[https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/2579-psp-replacement](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/2579-psp-replacement)

Kubelet Component Configs: \
[https://github.com/kubernetes/kubelet](https://github.com/kubernetes/kubelet)

PodOS documentation:

[https://kubernetes.io/docs/concepts/workloads/pods/#pod-os](https://kubernetes.io/docs/concepts/workloads/pods/#pod-os)

Windows Security Context Options: \
[https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#windowssecuritycontextoptions-v1-core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#windowssecuritycontextoptions-v1-core)

**Key Questions for Security Researchers Beyond Bug Hunting**

**Are all components covered by appropriate security testing?**

**Do the components have sufficient documentation for an administrator to effectively set them up securely?**

**Does this component have potential for any specific classes of bugs that need to be checked for that are often not caught by automated testing? (and if so, what are the results of your research)**

**Activities, Deliverables and Documentation**

It is key to understand the critical facets of this review to define success. The goal of this project is to both identify issues across many components and to incrementally improve testing for the long-term benefits of the kubernetes project and its ecosystem. For the components with higher priority, this means researching with both automated tools and manual review, identifying potential testing gaps and improvements, and building fuzzing harnesses and SAST rulesets if the component has significant gaps. \
 \
For lower priority components, it is crucial to document what tools, tests, and evaluation were completed, so that future work can build upon those foundations. It is essential that components that do not get reviewed due to time constraints are identified clearly so that future work can focus on those components.

If any issues that are found throughout this engagement appear to be high impact, the security contacts should be notified immediately of the issue for remediation through a secure channel. This is to reduce the effect of this engagement when the report is presented.

Recommendations should be clear and concise, and focus on low maintenance solutions that are without cost. (Or low cost if expenses cannot be avoided.) Free and open source solutions should be a priority.

Any fuzzing harnesses, custom SAST rulesets, or any other custom code developed during this engagement should be donated to the project at the end of this engagement without cost.

At the end of this engagement a public report will be generated by the audit team that details all of the work done, the security findings, and all of the recommendations. This document will be published after all issues are resolved or OSTIF consensus determines that disclosure time limits have been reached.
