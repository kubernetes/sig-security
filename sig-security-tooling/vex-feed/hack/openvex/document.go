// Package openvex re-exports the OpenVEX document/statement types from
// github.com/openvex/go-vex and adds the Load/Save helpers the vex-feed hack
// tools need.
package openvex

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

// Document is a single OpenVEX document: either a per-issue source file
// under files/, or the combined feed.
type (
	Document        = vex.VEX
	Metadata        = vex.Metadata
	Statement       = vex.Statement
	Product         = vex.Product
	Subcomponent    = vex.Subcomponent
	Component       = vex.Component
	Vulnerability   = vex.Vulnerability
	VulnerabilityID = vex.VulnerabilityID
	Status          = vex.Status
	Justification   = vex.Justification
)

// ContextV02 is the OpenVEX v0.2.0 JSON-LD context every document in this
// repo declares.
const ContextV02 = vex.Context + "/v" + vex.SpecVersion

// DefaultAuthor is the author every document in this repo declares.
const DefaultAuthor = "kubernetes maintainers"

// BuildFeedHint is the command hint printed after writing a per-issue
// document, pointing at the next step in the workflow.
const BuildFeedHint = "go run ./hack/build-feed"

// Load reads and parses a single OpenVEX document from path.
func Load(path string) (Document, error) {
	doc, err := vex.Load(path)
	if err != nil {
		return Document{}, fmt.Errorf("failed to load %s: %w", path, err)
	}
	return *doc, nil
}

// htmlEscapes undoes the HTML escaping vex.VEX.MarshalJSON always applies to
// <, >, and & when it normalizes timestamps: that method builds its result
// with the package-level json.Marshal, which is hardcoded to escape HTML and
// ignores ToJSON's own SetEscapeHTML(false). These are the only three
// sequences Go's json encoder ever produces for those runes, so replacing
// them back is safe -- legitimate document text cannot contain this literal
// six-character form other than as this escaping artifact.
var htmlEscapes = []struct{ escaped, raw string }{
	{`\` + `u003c`, "<"},
	{`\` + `u003e`, ">"},
	{`\` + `u0026`, "&"},
}

// Save writes doc to path as 2-space-indented JSON with a single trailing
// newline. A nil doc.Timestamp is defaulted to now: go-vex marshals a nil
// Timestamp as "" rather than omitting it, which then fails to parse back
// on Load.
func Save(path string, doc Document) error {
	if doc.Timestamp == nil {
		now := time.Now()
		doc.Timestamp = &now
	}
	var buf bytes.Buffer
	if err := doc.ToJSON(&buf); err != nil {
		return fmt.Errorf("failed to marshal document for %s: %w", path, err)
	}
	b := buf.Bytes()
	for _, r := range htmlEscapes {
		b = bytes.ReplaceAll(b, []byte(r.escaped), []byte(r.raw))
	}
	// #nosec G304 -- callers only ever pass a fixed repo-relative constant
	// or a glob result derived from a fixed pattern, never raw external input.
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}
