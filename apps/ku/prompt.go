package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) } // #nosec G115 -- fd fits in int

// stdin is the one buffered reader of a.in, so a second prompt does not lose what the first one buffered.
func (a *app) stdin() *bufio.Reader {
	if a.stdinR == nil {
		a.stdinR = bufio.NewReader(a.in)
	}
	return a.stdinR
}

// confirm asks a y/N question. --yes skips it; without a terminal it refuses rather than guessing.
func (a *app) confirm(question string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !a.isTTY {
		return false, errors.New("add --yes to confirm when there is no terminal")
	}
	fmt.Fprintf(a.err, "%s (y/N) ", question)
	line, _ := a.stdin().ReadString('\n')
	l := strings.ToLower(strings.TrimSpace(line))
	return l == "y" || l == "yes", nil
}

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
