package main

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
)

func setup() (*config.Config, error) {
	color.New(color.BgWhite).Println("Set up master password")
	color.Yellow(Wrap("⚠ Forgetting your master password will result in data loss.  Be sure to write it down somewhere safe.", 60))
	fmt.Println()
	password, err := setupMasterPassword()
	if err != nil {
		return nil, err
	}

	fmt.Println()
	color.New(color.BgWhite).Println("Set up config")
	fmt.Println()

	cfg, err := setupConfig(password)
	if err != nil {
		return nil, err
	}

	color.Green("✓ Configuration saved successfully!")

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(0, 1).
		BorderForeground(lipgloss.Color("63"))

	fmt.Println(boxStyle.Render(fmt.Sprintf("Public Key: %s", cfg.AgePublicKey)))

	return cfg, nil
}

func setupConfig(password string) (*config.Config, error) {
	questions := []*survey.Question{
		{
			Name: "keyid",
			Prompt: &survey.Input{
				Message: "Backblaze Key ID:",
			},
			Validate: survey.Required,
		},
		{
			Name: "appkey",
			Prompt: &survey.Password{
				Message: "Backblaze Application Key:",
			},
			Validate: survey.Required,
		},
		{
			Name: "bucketname",
			Prompt: &survey.Input{
				Message: "Backblaze Bucket Name:",
			},
			Validate: survey.Required,
		},
		{
			Name: "region",
			Prompt: &survey.Input{
				Message: "Backblaze Region:",
				Default: "us-west-002",
				Help:    "e.g., us-west-002, us-east-005, eu-central-003",
			},
			Validate: survey.Required,
		},
	}

	var configAnswers struct {
		KeyID      string
		AppKey     string
		BucketName string
		Region     string
	}

	if err := survey.Ask(questions, &configAnswers); err != nil {
		return nil, err
	}

	fmt.Println("\nℹ Generating encryption keys...")

	publicKey, privateKey, err := enc.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption keys: %w", err)
	}

	masterKey := make([]byte, 64)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	cfg := config.Config{
		KeyID:         configAnswers.KeyID,
		AppKey:        configAnswers.AppKey,
		BucketName:    configAnswers.BucketName,
		Region:        configAnswers.Region,
		AgePublicKey:  publicKey,
		AgePrivateKey: privateKey,
		MasterKey:     masterKey,
	}

	if err := config.Save(cfg, password); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setupMasterPassword() (string, error) {

	masterPasswordQuestions := []*survey.Question{
		{
			Name: "password",
			Prompt: &survey.Password{
				Message: "Master Password:",
			},
			Validate: survey.Required,
		},
		{
			Name: "confirm",
			Prompt: &survey.Password{
				Message: "Confirm Master Password:",
			},
			Validate: survey.Required,
		},
	}

	var passwordAnswers struct {
		Password string
		Confirm  string
	}

	if err := survey.Ask(masterPasswordQuestions, &passwordAnswers); err != nil {
		return "", err
	}

	if passwordAnswers.Password != passwordAnswers.Confirm {
		color.Red("Passwords do not match")
		return "", errors.New("passwords do not match")
	}

	color.Green("✓ Master password created successfully!")

	return passwordAnswers.Password, nil
}

// WrapExact wraps text to the given width while preserving all original
// spacing between tokens (spaces, tabs) and keeping newlines intact.
// - Breaks only at whitespace boundaries (space/tab/newline).
// - Does NOT collapse multiple spaces.
// - Splits overlong non-space tokens if they exceed width.
// Note: tabs count as 1 column; expand yourself beforehand if needed.
func Wrap(text string, width int) string {
	if width <= 1 || text == "" {
		return text
	}

	tokens := tokenize(text)

	var out []rune
	lineLen := 0

	emitNewline := func() {
		out = append(out, '\n')
		lineLen = 0
	}

	appendRunes := func(rs []rune) {
		out = append(out, rs...)
		lineLen += len(rs)
	}

	for _, t := range tokens {
		if t.newline {
			// Hard line break; preserve exactly.
			emitNewline()
			continue
		}

		rs := []rune(t.s)
		tLen := len(rs)

		// If token fits, append as-is.
		if lineLen+tLen <= width {
			// Avoid leading spaces: drop if line start and token is space.
			if !(lineLen == 0 && t.space) {
				appendRunes(rs)
			}
			continue
		}

		// Doesn't fit on this line.
		if t.space {
			// Break line and drop leading spaces on the next line.
			emitNewline()
			continue
		}

		// Non-space token. If current line has content, break first.
		if lineLen > 0 {
			emitNewline()
		}

		// Token may still be longer than width; split it into chunks.
		for start := 0; start < tLen; {
			end := start + width
			if end > tLen {
				end = tLen
			}
			appendRunes(rs[start:end])
			start = end
			if start < tLen {
				emitNewline()
			}
		}
	}

	return string(out)
}

func tokenize(s string) []struct {
	s       string
	space   bool
	newline bool
} {
	var toks []struct {
		s       string
		space   bool
		newline bool
	}

	var cur []rune
	mode := 0 // 0=none, 1=space, 2=nonspace

	flush := func(nl bool) {
		if len(cur) > 0 {
			toks = append(toks, struct {
				s       string
				space   bool
				newline bool
			}{
				s:       string(cur),
				space:   mode == 1,
				newline: false,
			})
			cur = cur[:0]
		}
		if nl {
			toks = append(toks, struct {
				s       string
				space   bool
				newline bool
			}{
				s:       "\n",
				space:   false,
				newline: true,
			})
		}
		mode = 0
	}

	for _, r := range s {
		switch r {
		case '\n':
			flush(true)
		case ' ', '\t':
			if mode != 1 {
				flush(false)
				mode = 1
			}
			cur = append(cur, r)
		default:
			if mode != 2 {
				flush(false)
				mode = 2
			}
			cur = append(cur, r)
		}
	}
	flush(false)
	return toks
}
