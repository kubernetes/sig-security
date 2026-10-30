package github

// KubernetesIssue contains the source issue fields used by the bridge.
type KubernetesIssue struct {
	Number   int
	Title    string
	Body     string
	URL      string
	State    string
	Comments []Comment
}

type Comment struct {
	Body string
}
