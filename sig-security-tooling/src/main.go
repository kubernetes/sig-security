package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	KeyCTRL_C = 3 // ETX (End of Text)
)

func main() {
	if err := Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func Run() error {
	if len(os.Args) < 2 {
		return errors.New("please give CVE-YYYY-NNNNN as argument")
	}

	cve := strings.ToUpper(os.Args[1])
	if !regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`).MatchString(cve) {
		return errors.New("invalid CVE name")
	}

	var state State
	// Let's try to find a local saved state
	file, err := os.Open(cve)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to open file %s: %w", cve, err)
		}
		state = NewState(cve)
		state.SetStatus(fmt.Sprintf("could not find file for %s, starting from fresh state", state.CVE))
	} else {
		state, err = restoreStateFromFile(file, cve)
		if err != nil {
			return fmt.Errorf("failed to restore state from file %s: %w", file.Name(), err)
		}
		state.SetStatus(fmt.Sprintf("restored state from existing file %s", state.CVE))
	}

	for {
		fmt.Printf("%s\n", state)

		fmt.Printf("status: %s\n", state.GetStatus())
		state.ClearStatus()

		fmt.Print("(0-9), (e)dit, (s)ave, e(x)port, (q)uit: ")
		pressedKey, err := PromptUserOneByte()
		if err != nil {
			return err
		}
		// It's important to use %q here to escape any unsafe bytes that
		// would mess up the terminal output
		fmt.Printf("%q", pressedKey)

		switch pressedKey {
		case stepSummary.ASCII():
			fallthrough
		case stepCVSS.ASCII():
			fallthrough
		case stepDescription.ASCII():
			fallthrough
		case stepVulnerable.ASCII():
			fallthrough
		case stepAffectedVersions.ASCII():
			fallthrough
		case stepFixedVersions.ASCII():
			fallthrough
		case stepMitigate.ASCII():
			fallthrough
		case stepDetection.ASCII():
			fallthrough
		case stepAdditionalDetails.ASCII():
			fallthrough
		case stepAcknowledgements.ASCII():
			step := StepNumber(pressedKey - '0')
			state.GoToFocus(step)
			state.SetStatus(fmt.Sprintf("jumped to step %d: %q", step, state.GetCurrentStep().Title))
		case 'e', 'E':
			modifiedStep := state.GetCurrentStep()
			fromEditor, err := ReadFromEditor(modifiedStep.Value, modifiedStep.Title, modifiedStep.Help, modifiedStep.Example)
			if err != nil {
				return fmt.Errorf("failed to read from editor: %w", err)
			}
			// var out bytes.Buffer
			// goldmark.Convert(fromEditor, &out)
			// modifiedStep.Value = out.String()
			modifiedStep.Value = string(fromEditor)
			if modifiedStep.Validate != nil {
				err = modifiedStep.Validate(modifiedStep.Value)
				if err != nil {
					state.SetStatus(fmt.Sprintf("invalid value for %d: %s", state.GetFocus(), err))
					break
				}
			}
			state.SetStatus(fmt.Sprintf("edited step %d", state.GetFocus()))
			state.SetCurrentStep(modifiedStep)
			state.NextFocus()
		case 'x', 'X':
			fmt.Print(" (i)ssue, e(m)ail, (s)lack? ")
			pressedKey, err := PromptUserOneByte()
			if err != nil {
				return err
			}
			fmt.Printf("%q", pressedKey)

			var template string
			switch pressedKey {
			case 'i', 'I':
				template = "issue"
			case 'm', 'M':
				template = "email"
			case 's', 'S':
				template = "slack"
			}
			if template == "" {
				state.SetStatus(fmt.Sprintf("invalid export format %c", pressedKey))
				break
			}
			output, err := export(filepath.Join(templateFolder, template+".tmpl"), state)
			if err != nil {
				state.SetStatus(err.Error())
				break
			}

			fileName := state.CVE + "." + template
			err = os.WriteFile(fileName, output, 0666)
			if err != nil {
				state.SetStatus(fmt.Sprintf("failed to write to file %s: %s", fileName, err.Error()))
				break
			}
			state.SetStatus(fmt.Sprintf("successfully exported to file %s", fileName))
		case 's', 'S':
			err := state.FlushToDisk()
			if err != nil {
				return fmt.Errorf("failed to flush state to disk: %w", err)
			}
			state.SetStatus(fmt.Sprintf("successfully saved to file %s", state.CVE))
		case KeyCTRL_C, 'q', 'Q':
			if state.dirty {
				state.SetStatus("please confirm to quit without saving to disk")
				state.dirty = false
				break
			}
			fmt.Println()
			return nil
		default:
			state.SetStatus(fmt.Sprintf("invalid command %q", pressedKey))
		}

		fmt.Printf("\n%s\n", strings.Repeat("=", len(state.CVE)))
	}
}
