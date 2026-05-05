package main

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
	"k8s.io/kubernetes/sig-security/srctl/state"
)

const (
	HTMLCommentBegin = "<!--"
	HTMLCommentEnd   = "-->"
)

var commonEditors = []string{"vi", "vim", "emacs", "nano"}

func PromptUserOneByte() (b byte, returnedErr error) {
	fileDesc := os.Stdin.Fd()
	if fileDesc > math.MaxInt {
		return 0, fmt.Errorf("stdin fd value %d overflows int", fileDesc)
	}
	fileDescInt := int(fileDesc)
	oldState, err := term.MakeRaw(fileDescInt)
	if err != nil {
		return 0, fmt.Errorf("failed to put terminal in raw mode: %w", err)
	}
	defer func() {
		err := term.Restore(fileDescInt, oldState)
		if err != nil {
			returnedErr = fmt.Errorf("failed to restore the terminal: %w", err)
		}
	}()

	var bytes = make([]byte, 1)
	_, err = os.Stdin.Read(bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to read from stdin: %w", err)
	}
	return bytes[0], nil
}

func instructions(number state.StepNumber, title, help, example string) []byte {
	var buf bytes.Buffer

	buf.WriteString("\n<!--\n")
	buf.WriteString("Please enter the text for your changes. Empty lines and HTML\n")
	buf.WriteString("comments lines will be ignored. An empty text aborts the change.\n\n")
	s := fmt.Sprintf("%d) %s\n\n", number, title) // for linter
	buf.WriteString(s)
	for l := range strings.SplitSeq(help, "\n") {
		buf.WriteString(l + "\n")
	}
	buf.WriteString("\nExample:\n")
	for l := range strings.SplitSeq(example, "\n") {
		buf.WriteString(l + "\n")
	}
	buf.WriteString("-->")

	return buf.Bytes()
}

func firstAvailableEditor(candidates []string) (string, bool) {
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c, true
		}
	}
	return "", false
}

func ReadFromEditor(number state.StepNumber, value, title, help, example string) (b []byte, returnedErr error) {
	tmpFile, err := os.CreateTemp("", ".tmp.*.md")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		err := os.Remove(tmpFile.Name())
		if err != nil {
			returnedErr = fmt.Errorf("failed to remove file %s: %w", tmpFile.Name(), err)
		}
	}()

	var initialContent bytes.Buffer
	initialContent.WriteString(value)
	initialContent.WriteString("\n")
	initialContent.Write(instructions(number, title, help, example))
	err = os.WriteFile(tmpFile.Name(), initialContent.Bytes(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to write the placeholder: %w", err)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		if firstEditor, found := firstAvailableEditor(commonEditors); found {
			editor = firstEditor
		} else {
			return nil, fmt.Errorf("couldn't find an available editor in PATH from list %v, please set EDITOR", commonEditors)
		}
	}

	// caution: the binary starts whatever EDITOR is provided by user.
	// #nosec G204
	// #nosec G702
	cmd := exec.Command(editor, tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run the editor: %w", err)
	}

	// Re-open the file to read from the beginning after editor modified it
	editedFile, err := os.Open(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to re-open file %s: %w", tmpFile.Name(), err)
	}
	defer func() {
		if err := editedFile.Close(); err != nil {
			returnedErr = fmt.Errorf("failed to close file %s: %w", tmpFile.Name(), err)
		}
	}()

	scanner := bufio.NewScanner(editedFile)
	var out bytes.Buffer
	inComment := false
	for scanner.Scan() {
		line := scanner.Text()
		trimedLine := strings.TrimSpace(line)

		// Let's simplify how we treat HTML comments here and reasonate on lines
		if strings.Contains(trimedLine, HTMLCommentBegin) {
			inComment = true
		}
		if strings.Contains(trimedLine, HTMLCommentEnd) {
			inComment = false
			continue
		}
		if inComment {
			continue
		}

		out.WriteString(line + "\n")
	}

	if scanner.Err() != nil {
		return nil, fmt.Errorf("failed to scan file %s: %w", tmpFile.Name(), scanner.Err())
	}

	return bytes.TrimSpace(out.Bytes()), nil
}
