// Package github retrieves Kubernetes issues using go-github.
package github

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v93/github"
)

// GitHubClient handles interactions with the GitHub API.
type GitHubClient struct {
	client *github.Client
}

// NewGitHubClient creates a new GitHub API client using the GITHUB_TOKEN environment variable
func NewGitHubClient() (*GitHubClient, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	// Create authenticated client
	client, error := github.NewClient(github.WithAuthToken(token))
	if error != nil {
		return nil, fmt.Errorf("creating GitHub client: %w", error)
	}
	return &GitHubClient{
		client: client,
	}, nil
}

// SearchIssues searches for issues using GitHub's search API with the given query
func (gc *GitHubClient) SearchIssues(query string) ([]KubernetesIssue, error) {
	ctx := context.Background()
	options := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	var issues []KubernetesIssue
	for {
		result, response, err := gc.client.Search.Issues(ctx, query, options)
		if err != nil {
			return nil, fmt.Errorf("searching for issues: %w", err)
		}
		for _, ghIssue := range result.Issues {
			issues = append(issues, KubernetesIssue{
				Number: ghIssue.GetNumber(),
				Title:  ghIssue.GetTitle(),
				Body:   ghIssue.GetBody(),
				URL:    ghIssue.GetHTMLURL(),
				State:  ghIssue.GetState(),
			})
		}
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}

	return issues, nil
}

// GetIssueDetails fetches detailed information about a specific issue,
// including all comments
func (gc *GitHubClient) GetIssueDetails(owner, repo string, issueNumber int) (*KubernetesIssue, error) {
	ctx := context.Background()

	// Fetch the issue
	ghIssue, _, err := gc.client.Issues.Get(ctx, owner, repo, issueNumber)
	if err != nil {
		return nil, fmt.Errorf("fetching issue #%d: %w", issueNumber, err)
	}

	options := &github.IssueListCommentsOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	// Convert to KubernetesIssue
	issue := &KubernetesIssue{
		Number: ghIssue.GetNumber(),
		Title:  ghIssue.GetTitle(),
		Body:   ghIssue.GetBody(),
		URL:    ghIssue.GetHTMLURL(),
		State:  ghIssue.GetState(),
	}

	for {
		comments, response, err := gc.client.Issues.ListComments(ctx, owner, repo, issueNumber, options)
		if err != nil {
			return nil, fmt.Errorf("fetching comments for issue #%d: %w", issueNumber, err)
		}
		for _, comment := range comments {
			issue.Comments = append(issue.Comments, Comment{Body: comment.GetBody()})
		}
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}

	return issue, nil
}

// BuildSearchQuery constructs a GitHub search query for vex-unaffected-feed issues
func BuildSearchQuery(repo, label string) string {
	return fmt.Sprintf("is:issue label:%s repo:%s", label, repo)
}

// ParseOwnerRepo splits a repo string (e.g., "kubernetes/kubernetes") into owner and repo
func ParseOwnerRepo(repoStr string) (owner, repo string, err error) {
	parts := strings.Split(repoStr, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repo format: %s (expected owner/repo)", repoStr)
	}
	return parts[0], parts[1], nil
}
