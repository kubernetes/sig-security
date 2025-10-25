package main

import (
	"bytes"
	"fmt"
	"maps"
	"text/template"

	"github.com/yuin/goldmark"
)

const (
	templateFolder = "templates"
)

func export(templatePath string, state State) ([]byte, error) {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed parsing template file %s: %w", templatePath, err)
	}
	var buf bytes.Buffer

	convertedState := maps.Clone(state.Steps)
	for key, step := range convertedState {
		if !step.Multiline {
			continue
		}
		var buf bytes.Buffer
		goldmark.Convert([]byte(step.Value), &buf)
		step.Value = buf.String()
		convertedState[key] = step
	}

	err = tmpl.Execute(&buf, convertedState)
	if err != nil {
		return nil, fmt.Errorf("failed to execute the template: %w", err)
	}
	return buf.Bytes(), nil
}
