package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"k8s.io/kubernetes/sig-security/srctl/state"
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

	var st state.Internal
	// Let's try to find a local saved state
	file, err := os.Open(cve + ".json")
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to open file %s: %w", cve, err)
		}
		st = state.New(cve)
		st.SetStatus(fmt.Sprintf("could not find file for %s, starting from fresh state", st.CVE))
	} else {
		st, err = state.RestoreFromFile(file, cve)
		if err != nil {
			return fmt.Errorf("failed to restore state from file %s: %w", file.Name(), err)
		}
		st.SetStatus(fmt.Sprintf("restored state from existing file %s", st.CVE))
	}

	for {
		fmt.Print("\033[H\033[2J") // Clear screen
		fmt.Printf("%s\n", st)

		fmt.Printf("Status: %s\n", st.GetStatus())
		st.ClearStatus()

		fmt.Print("Enter or (0-9) to edit, (s)ave, e(x)port, (q)uit: ")
		pressedKey, err := PromptUserOneByte()
		if err != nil {
			return err
		}
		// It's important to use %q here to escape any unsafe bytes that
		// would mess up the terminal output
		fmt.Printf("%q", pressedKey)

		switch pressedKey {
		case state.StepSummary.ASCII():
			fallthrough
		case state.StepCVSS.ASCII():
			fallthrough
		case state.StepDescription.ASCII():
			fallthrough
		case state.StepVulnerable.ASCII():
			fallthrough
		case state.StepAffectedVersions.ASCII():
			fallthrough
		case state.StepUpgrade.ASCII():
			fallthrough
		case state.StepMitigate.ASCII():
			fallthrough
		case state.StepDetection.ASCII():
			fallthrough
		case state.StepAdditionalDetails.ASCII():
			fallthrough
		case state.StepAcknowledgements.ASCII():
			step := state.StepNumber(pressedKey - '0')
			st.GoToFocus(step)
			fallthrough
		case '\r':
			modifiedStep := st.GetCurrentStep()
			fromEditor, err := ReadFromEditor(modifiedStep.ID, modifiedStep.Value, modifiedStep.Title, modifiedStep.Help, modifiedStep.Example)
			if err != nil {
				return fmt.Errorf("failed to read from editor: %w", err)
			}
			modifiedStep.Value = string(fromEditor)
			if modifiedStep.Validate != nil {
				err = modifiedStep.Validate(modifiedStep.Value)
				if err != nil {
					st.SetStatus(fmt.Sprintf("invalid value for %d: %s", st.GetFocus(), err))
					break
				}
			}
			st.SetStatus(fmt.Sprintf("edited step %d", st.GetFocus()))
			st.SetCurrentStep(modifiedStep)
			st.NextFocus()
		case 'x', 'X':
			fmt.Print(" (i)ssue, e(m)ail, (s)lack? ")
			pressedKey, err := PromptUserOneByte()
			if err != nil {
				return err
			}
			fmt.Printf("%q", pressedKey)

			data, err := st.ToProcessedData()
			if err != nil {
				st.SetStatus(err.Error())
				break
			}

			var ext string
			var output []byte
			switch pressedKey {
			case 'i', 'I':
				ext = "issue.md"
				output, err = data.ToIssue()
				if err != nil {
					st.SetStatus(err.Error())
					break
				}
			case 'm', 'M':
				ext = "email.md"
			case 's', 'S':
				ext = "slack.md"
			}
			if ext == "" {
				st.SetStatus(fmt.Sprintf("invalid export format %c", pressedKey))
				break
			}

			fileName := st.CVE + "." + ext
			err = os.WriteFile(fileName, output, 0666)
			if err != nil {
				st.SetStatus(fmt.Sprintf("failed to write to file %s: %s", fileName, err.Error()))
				break
			}
			st.SetStatus(fmt.Sprintf("successfully exported to file %s", fileName))
		case 's', 'S':
			err := st.ExportToFile()
			if err != nil {
				return fmt.Errorf("failed to flush state to disk: %w", err)
			}
			st.SetStatus(fmt.Sprintf("successfully saved to file %s.json", st.CVE))
			// fmt.Println(st.ToProcessedData())
		case 'j':
			st.NextFocus()
			st.SetStatus(fmt.Sprintf("scrolled to %d", st.GetFocus()))
		case 'k':
			st.PreviousFocus()
			st.SetStatus(fmt.Sprintf("scrolled to %d", st.GetFocus()))
		case '.':
			data, err := st.ToProcessedData()
			if err != nil {
				st.SetStatus(err.Error())
				break
			}
			st.SetStatus(fmt.Sprintf("%#v", data))
		case KeyCTRL_C, 'q', 'Q':
			if st.Dirty {
				st.SetStatus("please confirm to quit without saving to disk")
				st.Dirty = false
				break
			}
			fmt.Println()
			return nil
		default:
			st.SetStatus(fmt.Sprintf("invalid command %q", pressedKey))
		}

		fmt.Printf("\n%s\n", strings.Repeat("=", len(st.CVE)))
	}
}
