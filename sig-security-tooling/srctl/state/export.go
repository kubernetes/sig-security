package state

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"
)

var (
	//go:embed issue.tmpl
	rawIssueTemplate string
	issueTemplate    = template.Must(template.New("issue").Parse(rawIssueTemplate))
)

func (d CVEData) ToIssue() ([]byte, error) {
	var buf bytes.Buffer

	err := issueTemplate.Execute(&buf, d)
	if err != nil {
		return nil, fmt.Errorf("failed to execute the template: %w", err)
	}
	return buf.Bytes(), nil
}
