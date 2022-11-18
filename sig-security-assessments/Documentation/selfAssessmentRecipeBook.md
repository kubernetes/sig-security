Yay! You have decided to do a Self-Assessment and make your corner of Kubernetes more secure! Here is an outline of the journey to get to a successful Self-Assessment.

1.	Set yourself up for success – build your team and get organized
a.	Figure out who can do this self-assessment with you. You will need a counterpart who owns the project (e.g. CAPI) and is an expert in it. This is probably the requestor of the self-assessment.
b.	Make sure that you and your counterpart each have a back up person assigned who attends all the meetings and is involved in the assessment. Two heads are better than one, and redundancy means that if someone can’t make a meeting for whatever reason, that you can still make progress.
c.	To get further participation, advertise in other SIG meetings. Aim for a minimum of 4 people (you, your counterpart/the requestor, and a backup for each), and a maximum of 8. Otherwise, the decision making process can be unwieldly.
d.	Create a google doc for meeting notes for future and past meetings for tracking. Share these notes in the SIG Security channel, TAG security channel, and the appropriate Kubernetes slack channel for the project you are assessing.
2.	Get started!
a.	Once you have your collateral and your team together, set up a kickoff meeting with everyone. It is likely that not everyone will show up. That’s ok! 
b.	Document in the meeting notes who does, and create a recurring meeting series of about 6 meetings for those people (plus you, of course) to continue working through the assessment.
c.	These sessions can be ad hoc and should be set for whatever timing works for the group. It may take fewer or more meetings than 6 to complete the assessment. 6 is just a suggestion 
3.	The Assessment
a.	Step one: Draw an architecture diagram for the main workflows in the project. This step will show you the areas you can potentially assess. Xcalidraw is a great tool for this!
b.	Step two: decide what to assess. Deciding the scope of the assessment is essential to making it successful. This decision will keep you focused and ensure you make forward progress. Helpful questions when thinking about what to assess:
i.	What workflows are used most?
ii.	What workflows does the community want a security assessment of?
iii.	What expertise does the team doing the assessment have? Does it match any of the potential flows? Try to get matching expertise for the scope!
c.	Step three: with the scope selected, come up with threats that are reasonable and logical for the projects. 
i.	Use the TAG Self-Assessment template to write up the report. You can use Google Docs or HackMD – whatever the project team is most comfortable with. 
ii.	Once the team is happy with the above doc, convert it into a markdown PR and assign reviewers.
iii.	Now is a good time to start writing a blog post to share once the review is done.
d.	Step 4: Once the reviews are complete, the self-assessment can be merged!
e.	Step 5: Complete and publish your blog!

