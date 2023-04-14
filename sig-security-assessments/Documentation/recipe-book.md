# Recipe Book 👩‍🍳
🎉Yay! You have decided to do a Self-assessment and make your corner of Kubernetes more secure! We are so happy 
to have you here. Below is an outline of the journey to get to a successful Self-assessment.

## Preparation
Set yourself up for success – build your team and get organized
1.	Open a Security Assessment Request using the [issue template.](https://github.com/kubernetes/sig-security/issues/new/choose)
1. Figure out who can do this Self-assessment with you. You will need a security champion and a counterpart who owns the 
project and is an expert in it. If you are requesting a Security Self-assessment you can reach out to the team in
[#sig-security](https://kubernetes.slack.com/messages/sig-security), and [#sig-security-assessments](https://kubernetes.slack.com/archives/C0441E11REC) to see if there is someone interested in helping to
champion the assessment.
1.	Make sure that you and your counterpart each have a back-up person assigned who attends all the meetings and is 
involved in the assessment. Two heads are better than one, and redundancy means that if someone can’t make a meeting 
for whatever reason, that you can still make progress.
1.	To get further participation, advertise in SIG meetings and channels for the project, as well as SIG Security. Aim for a minimum of 4 
people (a project expert, a security champion, and a backup for each), and a maximum of 8. This ensures that there is 
not overwhelming burden on any one individual but allows for a smooth decision-making process.
1. Once you have a dedicated group of individuals ready to start the Security Assessment you can open an issue to request
a Slack channel for the project specific assessment - here's an [example](https://github.com/kubernetes/community/pull/7015).
1.	Create a Google doc for meeting notes using the
[Kubernetes community meeeting notes template](https://github.com/kubernetes/community/blob/master/events/community-meeting.md) 
## Meetings
- Once you have your collateral and your team together, set up a kickoff meeting with everyone. It is likely that not 
everyone will show up. That’s ok!
- Keep meeting notes using the doc you created during the preparation phase.
- Create a recurring meeting series of about ~6 meetings (this is flexible and can be extended if necessary).
- These sessions can be ad hoc and should be set for whatever timing works for the group.
## The Assessment
### Step One
Draw a [data flow diagram](https://www.lucidchart.com/pages/data-flow-diagram) for the main workflows in the project. 
This step will show you the areas you can potentially assess, and allow the security champion to quickly gain context 
around how the project is structured - and where the biggest security concerns may be. 
[Excalidraw](https://excalidraw.com/) is a great tool for this!
### Step Two 
Decide what to assess - defining the scope of the assessment is essential to making it successful. This decision will
keep you focused and ensure you make forward progress. Helpful questions when thinking about what to assess:
- What workflows are used most?
- What workflows does the community want a security assessment of?
- What expertise does the team doing the assessment have? Does it match any of the potential flows? 
Try to get matching expertise for the scope!
### Step Three 
Now that you have scope defined, we can come up with threats that are reasonable and logical for the projects.
- Use the [TAG Self-assessment template](https://github.com/cncf/tag-security/blob/main/assessments/guide/self-assessment.md) 
to write up the report. You can use Google Docs or HackMD – whatever the project team is most comfortable with. 
- Once the team is happy with the above doc, convert it into a markdown PR and assign reviewers.
- Now is a good time to start writing a [blog post](https://kubernetes.io/docs/contribute/new-content/blogs-case-studies/) to
share once the review is done.
### Step Four 
Once the reviews are complete, the Self-assessment can be merged!
### Step Five 
CLELEBRATE! Tell people about having completed the Self-assessment and make sure to complete and publish your blog!

