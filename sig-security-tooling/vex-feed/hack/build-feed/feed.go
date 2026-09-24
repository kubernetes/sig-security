package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

const (
	feedPath      = "kubernetes-vex-feed-draft.openvex.json"
	overridesPath = "hack/merge-overrides.json"
	feedID        = "https://raw.githubusercontent.com/kubernetes/sig-security/main/sig-security-tooling/vex-feed/kubernetes-vex-feed-draft.openvex.json"
)

// loadExistingFeed returns the on-disk feed and true, or (zero Document,
// false, nil) if it does not exist yet.
func loadExistingFeed(path string) (openvex.Document, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return openvex.Document{}, false, nil
		}
		return openvex.Document{}, false, fmt.Errorf("failed to stat %s: %w", path, err)
	}
	doc, err := openvex.Load(path)
	if err != nil {
		return openvex.Document{}, false, err
	}
	return doc, true, nil
}

// diffFeed reports whether the newly built statements/metadata differ from
// the on-disk feed.
func diffFeed(existing openvex.Document, exists bool, statements []openvex.Statement) (statementsChanged, metadataChanged bool) {
	if !exists {
		return true, true
	}
	statementsChanged = !reflect.DeepEqual(existing.Statements, statements)
	metadataChanged = existing.Context != openvex.ContextV02 || existing.ID != feedID || existing.Author != openvex.DefaultAuthor
	return statementsChanged, metadataChanged
}
