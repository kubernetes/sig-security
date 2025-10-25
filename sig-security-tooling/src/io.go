package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/term"
)

const helpMsg = `# Please enter the text for your changes. Empty lines and lines
# starting with '#' will be ignored. An empty text aborts the change.`

func PromptUserOneByte() (byte, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return 0, fmt.Errorf("failed to put terminal in raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var b = make([]byte, 1)
	os.Stdin.Read(b)
	return b[0], nil
}

func promptUserNumber() (int, error) {
	reader := bufio.NewReader(os.Stdin)

	input, err := reader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("failed reading input: %w", err)
	}

	out, err := strconv.ParseInt(strings.TrimSpace(input), 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to parse integer %s: %w", input, err)
	}
	return int(out), nil
}

func writeComments(title, help, example string) []byte {
	var buf bytes.Buffer

	buf.WriteString(helpMsg + "\n")
	buf.WriteString("#\n")
	buf.WriteString(fmt.Sprintf("# %s\n", title))
	buf.WriteString("#\n")
	for l := range strings.SplitSeq(help, "\n") {
		buf.WriteString(fmt.Sprintf("# %s\n", l))
	}
	buf.WriteString("#\n# Example:\n")
	for l := range strings.SplitSeq(example, "\n") {
		buf.WriteString(fmt.Sprintf("# %s\n", l))
	}

	return buf.Bytes()
}

func ReadFromEditor(value, title, help, example string) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", ".SRCTMP_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	var initialContent bytes.Buffer
	initialContent.WriteString(value)
	initialContent.WriteString("\n")
	initialContent.Write(writeComments(title, help, example))
	err = os.WriteFile(tmpFile.Name(), initialContent.Bytes(), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to write the placeholder: %w", err)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}

	cmd := exec.Command(editor, "-c", "set filetype=sh", tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run the editor: %w", err)
	}

	scanner := bufio.NewScanner(tmpFile)
	var out bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out.WriteString(line + "\n")
	}

	if scanner.Err() != nil {
		return nil, fmt.Errorf("failed to scan file %s: %w", tmpFile.Name(), err)
	}

	return bytes.TrimSpace(out.Bytes()), nil
}
