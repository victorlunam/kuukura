package main

import (
	"errors"
	"os"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) } // #nosec G115 -- fd fits in int

type hiddenModel struct {
	label     string
	input     textinput.Model
	value     string
	cancelled bool
}

func (m hiddenModel) Init() tea.Cmd { return textinput.Blink }

func (m hiddenModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEnter:
			m.value = m.input.Value()
			return m, tea.Quit
		case tea.KeyCtrlC, tea.KeyEsc:
			m.cancelled = true
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m hiddenModel) View() string { return m.label + " " + m.input.View() + "\n" }

// promptHidden reads a value with bullets echoed. The value never enters history or the process list.
func (a *app) promptHidden(label string) (string, error) {
	ti := textinput.New()
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Prompt = ""
	ti.CharLimit = 64 << 10
	ti.Focus()
	m, err := tea.NewProgram(hiddenModel{label: label, input: ti}, tea.WithOutput(os.Stderr)).Run()
	if err != nil {
		return "", err
	}
	hm := m.(hiddenModel)
	if hm.cancelled {
		return "", errors.New("cancelled")
	}
	return hm.value, nil
}
