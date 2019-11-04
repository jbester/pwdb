package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/howeyc/gopass"

	"github.com/jbester/pwdb/cmd/common"
	"github.com/jbester/pwdb/pkg/pwdb"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	get           = kingpin.Command("get", "Get the password for an account")
	account       = get.Arg("account", "Account Name").String()
	add           = kingpin.Command("add", "Add a new password")
	newAccount    = add.Arg("account", "Account Name").String()
	remove        = kingpin.Command("remove", "Remove a password account")
	removeAccount = remove.Arg("account", "Account Name").String()
	list          = kingpin.Command("list", "List accounts")
	passphrase    = kingpin.Command("passphrase", "Set or remove a passphrase")
)

func main() {
	var db *pwdb.Database
	var err error
	var cmd = kingpin.Parse()
	var password []byte
	var configPath = common.GetConfigFilaName()

	if !common.IsFolder(common.GetConfigDirectory()) {
		err := os.MkdirAll(configPath, 0700)
		if err != nil {
			common.Die(err.Error())
		}
	}

	if common.Exists(configPath) {
		if pwdb.IsEncrypted(configPath) {
			fmt.Printf("Enter password: ")
			password, err = gopass.GetPasswd()
			if err != nil {
				common.Die(err.Error())
			}
		}
		db, err = pwdb.LoadConfig(configPath, password)
		if err != nil {
			common.Die(err.Error())
		}
		if db.Passwords == nil {
			db.Passwords = make(map[string]pwdb.PasswordEntry)
		}
		if db.TotpAccounts == nil {
			db.TotpAccounts = make(map[string]pwdb.TotpEntry)
		}

	} else {
		db = pwdb.NewDatabase()
	}

	switch cmd {
	case add.FullCommand():
		var accountName string
		if *newAccount == "" {
			name, err := common.Prompt("Username: ")
			if err != nil {
				common.Die(err.Error())
			}
			accountName = strings.TrimSpace(name)
		} else {
			accountName = *newAccount
		}

		if _, ok := db.Passwords[accountName]; ok {
			common.Die(fmt.Sprintf("Account named '%v' already exists", accountName))
		}

		username, err := common.Prompt("Username: ")
		username = strings.TrimSpace(username)
		if err != nil {
			common.Die(err.Error())
		}
		fmt.Printf("Password: ")

		secret, err := gopass.GetPasswd()
		if err != nil {
			common.Die(err.Error())
		}

		db.Passwords[accountName] = pwdb.PasswordEntry{Username: username, Password: string(secret)}
		if !common.Exists(configPath) {
			fmt.Printf("Saving configuration to %v\n", configPath)
			password, err = common.GetNewPassword()
			if err != nil {
				common.Die(err.Error())
			}
		}
		pwdb.SaveConfig(configPath, db, password)

	case remove.FullCommand():
		if db == nil {
			common.Die("No config")
		}
		var accountName string
		if *removeAccount == "" {
			name, err := common.Prompt("Username: ")
			if err != nil {
				common.Die(err.Error())
			}
			accountName = strings.TrimSpace(name)
		} else {
			accountName = *removeAccount
		}

		if _, ok := db.Passwords[accountName]; ok {
			delete(db.Passwords, accountName)
			pwdb.SaveConfig(configPath, db, password)
		}

	case get.FullCommand():
		if *account == "" {
			fmt.Printf("Error: %v", err.Error())
		} else {
			if db == nil {
				common.Die("No config")
			}
			if account, ok := db.Passwords[*account]; ok {
				fmt.Println("Username:", account.Username)
				fmt.Println("Password:", account.Password)
				os.Exit(0)
			} else {
				common.Die("No account found")
			}
		}

	case passphrase.FullCommand():
		if db == nil {
			common.Die("No config")
		}
		password, err = common.GetNewPassword()
		if err != nil {
			common.Die(err.Error())
		}
		pwdb.SaveConfig(configPath, db, password)

	case list.FullCommand():
		if db == nil {
			fmt.Println("No config")
		} else {
			for name, _ := range db.Passwords {
				fmt.Println(name)
			}
		}
	}
}
