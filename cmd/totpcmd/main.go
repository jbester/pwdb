package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/jbester/pwdb/cmd/common"

	"github.com/jbester/pwdb/pkg/pwdb"

	"github.com/howeyc/gopass"
	"github.com/pkg/errors"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/jbester/pwdb/pkg/totp"
)

var (
	generate      = kingpin.Command("generate", "Generate a totp token for an account")
	account       = generate.Arg("account", "Account name").String()
	add           = kingpin.Command("add", "Add a new totp account")
	newAccount    = add.Arg("account", "Account name").String()
	remove        = kingpin.Command("remove", "Remove a totp account")
	removeAccount = remove.Arg("account", "Accout name").String()
	list          = kingpin.Command("list", "List accounts")
	passphrase    = kingpin.Command("passphrase", "Set or remove a passphrase")
)

func DoGenerate(secret string) error {
	// if no secret passed in - ask for one
	if secret == "" {
		s, err := common.Prompt("Enter secret: ")
		if err != nil {
			return errors.Wrap(err, "cannot process input")
		}
		secret = s
	}

	// remove whitespace
	var trimmedSecret = strings.TrimSpace(secret)

	// create secret
	totpSecret, err := totp.Base32Secret(trimmedSecret)
	if err != nil {
		fmt.Println(err.Error())
		return errors.Wrap(err, "cannot create totp generator")
	}

	// create the generator
	var generator = totp.NewGenerator(totpSecret)

	// generate the current token
	token, err := generator.Now()
	fmt.Printf("%06d\n", token)
	return err
}

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
			name, err := common.Prompt("Account name: ")
			if err != nil {
				common.Die(err.Error())
			}
			accountName = strings.TrimSpace(name)
		} else {
			accountName = *newAccount
		}

		if _, ok := db.TotpAccounts[accountName]; ok {
			common.Die(fmt.Sprintf("Username named '%v' already exists", accountName))
		}

		secret, err := common.Prompt("Secret: ")
		if err != nil {
			common.Die(err.Error())
		}
		secret = strings.TrimSpace(secret)

		db.TotpAccounts[accountName] = pwdb.TotpEntry{Secret: secret}
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
			name, err := common.Prompt("Account name: ")
			if err != nil {
				common.Die(err.Error())
			}
			accountName = strings.TrimSpace(name)
		} else {
			accountName = *removeAccount
		}

		if _, ok := db.TotpAccounts[accountName]; ok {
			delete(db.TotpAccounts, accountName)
			pwdb.SaveConfig(configPath, db, password)
		}

	case generate.FullCommand():
		if *account == "" {
			if err := DoGenerate(""); err != nil {
				fmt.Printf("Error: %v", err.Error())
			}
		} else {
			if db == nil {
				common.Die("No config")
			}
			if account, ok := db.TotpAccounts[*account]; ok {
				if err := DoGenerate(account.Secret); err != nil {
					fmt.Printf("Error: %v", err.Error())
				}
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
			for account, _ := range db.TotpAccounts {
				fmt.Println(account)
			}
		}
	}
}
