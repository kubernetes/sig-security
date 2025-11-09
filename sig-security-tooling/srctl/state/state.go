package state

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

// external is the struct used by the JSON marshaller to export the state to
// files to hide the implementation details to the user
type external struct {
	CVE   string              `json:"cve"`
	Steps map[StepName]string `json:"steps"`
}

func (s external) toInternal() Internal {
	newInternal := New(s.CVE)
	for key, value := range s.Steps {
		s, ok := newInternal.steps[key]
		if !ok {
			// unknown step, ignore
			continue
		}
		s.Value = value
		newInternal.steps[key] = s
	}
	return newInternal
}

type Internal struct {
	CVE   string
	steps map[StepName]Step

	focus  StepNumber
	status string
	Dirty  bool
}

func New(cve string) Internal {
	return Internal{
		CVE:   cve,
		steps: initSteps,
		focus: StepNumber(StepSummary),
	}
}

func (s Internal) String() string {
	out := &strings.Builder{}
	fmt.Fprintf(out, "%s\n", s.CVE)

	for stepNumber := range StepMax {
		step := s.steps[stepNumber.Name()]
		if step.ID == s.GetFocus() {
			fmt.Fprintf(out, "(%s%d%s) ", reverse, step.ID, notReverse)
		} else {
			fmt.Fprintf(out, "(%d) ", step.ID)
		}
		fmt.Fprintf(out, "%s: ", step.Title)
		if step.Value != "" {
			fmt.Fprintf(out, "%q", truncateMiddle(step.Value, maxWidthDisplay))
		}
		fmt.Fprintf(out, "\n")
	}
	return out.String()
}

func (s Internal) GetCurrentStep() Step {
	return s.steps[s.GetFocus().Name()]
}

func (s *Internal) SetCurrentStep(step Step) {
	s.steps[s.GetFocus().Name()] = step
	s.Dirty = true
}

func (s *Internal) NextFocus() {
	s.focus = (s.focus + 1) % StepMax
}

func (s *Internal) PreviousFocus() {
	s.focus = (s.focus - 1 + StepMax) % StepMax
}

func (s *Internal) GoToFocus(n StepNumber) StepNumber {
	s.focus = n % StepMax
	return s.focus
}

func (s Internal) GetFocus() StepNumber {
	return s.focus
}

func (s *Internal) SetStatus(message string) {
	s.status = message
}

func (s *Internal) ClearStatus() {
	s.status = ""
}

func (s Internal) GetStatus() string {
	return s.status
}

func (s Internal) toExternal() external {
	var newExternal external
	newExternal.CVE = s.CVE
	newExternal.Steps = map[StepName]string{}
	for key, step := range s.steps {
		newExternal.Steps[key] = step.Value
	}
	return newExternal
}

func (s Internal) ToJSON() ([]byte, error) {
	externalState := s.toExternal()
	return json.MarshalIndent(externalState, "", "	")
}

func (s *Internal) ExportToFile() error {
	bytes, err := s.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to convert to JSON: %w", err)
	}

	file, err := os.Create(s.CVE + ".json")
	if err != nil {
		return fmt.Errorf("failed to create new file %s: %w", s.CVE, err)
	}

	_, err = file.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %w", file.Name(), err)
	}
	s.Dirty = false
	return nil
}

func RestoreFromFile(file *os.File, cve string) (Internal, error) {
	bytes, err := io.ReadAll(file)
	if err != nil {
		return Internal{}, fmt.Errorf("failed to read file %s: %w", file.Name(), err)
	}

	var stateFromFile external
	err = json.Unmarshal(bytes, &stateFromFile)
	if err != nil {
		return Internal{}, fmt.Errorf("failed to unmarshal from file %s: %w", file.Name(), err)
	}

	if cve != stateFromFile.CVE {
		return Internal{}, fmt.Errorf("CVE provided %s and from file %s don't match", cve, stateFromFile.CVE)
	}

	return stateFromFile.toInternal(), nil
}

func truncateMiddle(s string, max int) string {
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
