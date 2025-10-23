package main

import "github.com/AlecAivazis/survey/v2"

func askMasterPassword() (string, error) {
	question := []*survey.Question{
		{
			Name: "password",
			Prompt: &survey.Password{
				Message: "Master Password:",
			},
		},
	}

	var password string
	if err := survey.Ask(question, &password); err != nil {
		return "", err
	}

	return password, nil
}
