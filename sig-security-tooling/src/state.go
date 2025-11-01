package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	reverse    = "\033[7m"
	notReverse = "\033[27m"

	maxWidthDisplay = 60
)

type State struct {
	CVE string `json:"cve"`
	// This field is exported for JSON marshalling,
	// please use the methods for accesses
	Steps map[string]Step `json:"steps"`

	focus  StepNumber
	status string
	dirty  bool
}

func NewState(cve string) State {
	return State{
		CVE:   cve,
		Steps: initSteps,
		focus: StepNumber(stepSummary),
	}
}

func (s State) String() string {
	out := &strings.Builder{}
	fmt.Fprintf(out, "%s\n", s.CVE)

	for stepNumber := range stepMax {
		step := s.Steps[stepNumber.String()]
		if step.ID == s.GetFocus() {
			fmt.Fprintf(out, "(%s%d%s) ", reverse, step.ID, notReverse)
		} else {
			fmt.Fprintf(out, "(%d) ", step.ID)
		}
		fmt.Fprintf(out, "%s: ", step.Title)
		if step.Value != "" {
			fmt.Fprintf(out, "%q", TruncateMiddle(step.Value, maxWidthDisplay))
		}
		fmt.Fprintf(out, "\n")
	}
	return out.String()
}

func (s State) GetCurrentStep() Step {
	return s.Steps[s.GetFocus().String()]
}

func (s *State) SetCurrentStep(step Step) {
	s.Steps[s.GetFocus().String()] = step
	s.dirty = true
}

func (s *State) NextFocus() {
	s.focus = (s.focus + 1) % stepMax
}

func (s *State) GoToFocus(n StepNumber) StepNumber {
	s.focus = n % stepMax
	return s.focus
}

func (s State) GetFocus() StepNumber {
	return s.focus
}

func (s *State) SetStatus(message string) {
	s.status = message
}

func (s *State) ClearStatus() {
	s.status = ""
}

func (s State) GetStatus() string {
	return s.status
}

func (s *State) FlushToDisk() error {
	bytes, err := json.MarshalIndent(s, "", "	")
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	file, err := os.Create(s.CVE)
	if err != nil {
		return fmt.Errorf("failed to create new file %s: %w", s.CVE, err)
	}

	_, err = file.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %w", file.Name(), err)
	}
	s.dirty = false
	return nil
}

func restoreStateFromFile(file *os.File, cve string) (State, error) {
	bytes, err := io.ReadAll(file)
	if err != nil {
		return State{}, fmt.Errorf("failed to read file %s: %w", file.Name(), err)
	}

	var stateFromFile State
	err = json.Unmarshal(bytes, &stateFromFile)
	if cve != stateFromFile.CVE {
		return State{}, fmt.Errorf("CVE provided %s and from file %s don't match", cve, stateFromFile.CVE)
	}
	// We can't just take stateFromFile, we need to fill unexported fields
	newState := NewState(cve)
	for key, stepFromFile := range stateFromFile.Steps {
		s, ok := newState.Steps[key]
		if !ok {
			// unknown step, ignore
			continue
		}
		s.Value = stepFromFile.Value
		newState.Steps[key] = s
	}
	// Exported fields might have overwritten missing steps
	if err != nil {
		return State{}, fmt.Errorf("failed to unmarshal from file %s: %w", file.Name(), err)
	}
	return newState, nil
}

func TruncateMiddle(s string, max int) string {
	if len(s) <= max || max <= 0 {
		return s
	}

	ellipsis := "[...]"
	if max <= len(ellipsis) {
		// max is too small to fit ellipsis, just truncate hard
		return s[:max]
	}

	// Remaining space for start + end
	remain := max - len(ellipsis)
	startLen := remain / 2
	endLen := remain - startLen

	return s[:startLen] + ellipsis + s[len(s)-endLen:]
}
