package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

const placeholderIssue = `TITLE: PLACEHOLDER ISSUE

---

/triage accepted
/lifecycle frozen
/area security
/kind bug
/committee security-response
`

func Run() error {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s CVE-YYYY-NNNNN\n", filepath.Base(os.Args[0]))
		fmt.Fprint(os.Stderr, "No CVE arg provided, printing placeholder issue template:\n\n")
		fmt.Print(placeholderIssue)
		return nil
	}

	cve := strings.TrimSuffix(strings.ToUpper(os.Args[1]), ".JSON")
	if !regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`).MatchString(cve) {
		return errors.New("invalid CVE name")
	}

	var st state.Internal
	// Let's try to find a local saved state.
	// #nosec G304
	// caution: the binary opens a file based on provided argument.
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
		st.SetStatus("restored state from existing file " + st.CVE)
	}

	for {
		fmt.Print("\033[H\033[2J") // Clear screen
		fmt.Printf("%s\n", st)

		fmt.Printf("Status: %s\n", st.GetStatus())
		st.ClearStatus()

		fmt.Print("Enter or (0-9,a-b) to edit, (s)ave, e(x)port, (q)uit: ")
		pressedKey, err := PromptUserOneByte()
		if err != nil {
			return err
		}
		// It's important to use %q here to escape any unsafe bytes that
		// would mess up the terminal output
		fmt.Printf("%q", pressedKey)

		// Handle step number keys (0-9, a-b) before the switch
		if step := state.StepNumberFromASCII(pressedKey); step >= 0 && step < state.StepMax {
			st.GoToFocus(step)
			pressedKey = '\r' // treat as enter to edit
		}

		switch pressedKey {
		case '\r':
			modifiedStep := st.GetCurrentStep()
			// Use PrePopulate value for editor if step value is empty
			editorValue := modifiedStep.Value
			if editorValue == "" && modifiedStep.PrePopulate != nil {
				editorValue = modifiedStep.PrePopulate()
			}
			fromEditor, err := ReadFromEditor(modifiedStep.ID, editorValue, modifiedStep.Title, modifiedStep.Help, modifiedStep.Example)
			if err != nil {
				return fmt.Errorf("failed to read from editor: %w", err)
			}
			modifiedStep.Value = string(fromEditor)
			if modifiedStep.Validate != nil {
				err = modifiedStep.Validate(modifiedStep.Value)
				if err != nil {
					st.SetStatus(fmt.Sprintf("invalid value for %c: %s", st.GetFocus().ASCII(), err))
					break
				}
			}
			st.SetStatus(fmt.Sprintf("edited step %c", st.GetFocus().ASCII()))
			st.SetCurrentStep(modifiedStep)
			st.NextFocus()
		case 'x', 'X':
			fmt.Print(" (i)ssue, e(m)ail, (s)lack or (a)ll? ")
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

			type export struct {
				ext    string
				toFunc func() ([]byte, error)
			}
			exports := map[byte][]export{
				'i': {{"issue.md", data.ToIssue}},
				'm': {{"email.md", data.ToEmail}},
				's': {{"slack.md", data.ToSlack}},
				'a': {
					{"issue.md", data.ToIssue},
					{"email.md", data.ToEmail},
					{"slack.md", data.ToSlack},
				},
			}

			key := pressedKey | 0x20 // lowercase
			toExport, ok := exports[key]
			if !ok {
				st.SetStatus(fmt.Sprintf("invalid export format %c", pressedKey))
				break
			}

			var exportedFiles []string
			for _, e := range toExport {
				output, err := e.toFunc()
				if err != nil {
					st.SetStatus(err.Error())
					break
				}
				fileName := st.CVE + "." + e.ext
				// Considering that the information could be confidential,
				// let's restrict the unix permissions to the current user.
				err = os.WriteFile(fileName, output, 0600)
				if err != nil {
					st.SetStatus(fmt.Sprintf("failed to write to file %s: %s", fileName, err.Error()))
					break
				}
				exportedFiles = append(exportedFiles, fileName)
			}
			if len(exportedFiles) == len(toExport) {
				st.SetStatus("successfully exported to: " + strings.Join(exportedFiles, ", "))
			}
		case 's', 'S':
			err := st.ExportToFile()
			if err != nil {
				return fmt.Errorf("failed to flush state to disk: %w", err)
			}
			st.SetStatus(fmt.Sprintf("successfully saved to file %s.json", st.CVE))
		case 'j':
			st.NextFocus()
			st.SetStatus(fmt.Sprintf("scrolled to %c", st.GetFocus().ASCII()))
		case 'k':
			st.PreviousFocus()
			st.SetStatus(fmt.Sprintf("scrolled to %c", st.GetFocus().ASCII()))
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
