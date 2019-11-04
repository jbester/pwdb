package common

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/howeyc/gopass"
)

func Die(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func Prompt(prompt string) (string, error) {
	fmt.Printf(prompt)
	var b = bufio.NewReader(os.Stdin)
	return b.ReadString('\n')
}

func GetConfigFilaName() string {
	return filepath.Join(GetConfigDirectory(), "accounts")
}

func GetConfigDirectory() string {
	var homeDirectory string
	if runtime.GOOS == "windows" {
		homeDirectory = os.Getenv("APPDATA")
	} else {
		homeDirectory = os.Getenv("HOME")
	}
	return filepath.Join(homeDirectory, ".pwdb")
}

func IsFolder(path string) bool {
	stat, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return stat.IsDir()
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func GetNewPassword() ([]byte, error) {
	var done = false
	var password []byte
	var err error
	for !done {
		fmt.Printf("Enter the passphrase (empty for no passphrase): ")
		password, err = gopass.GetPasswd()
		if err != nil {
			return nil, err
		}
		if string(password) != "" {
			fmt.Printf("Enter the same passphrase again: ")
			password2, err := gopass.GetPasswd()
			if err != nil {
				return nil, err
			}
			if string(password) != string(password2) {
				fmt.Println("Passwords don't match")
			} else {
				done = true
			}
		} else {
			done = true
		}
	}
	return password, nil
}
