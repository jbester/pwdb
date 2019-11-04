package pwdb

// Totp Entry
type TotpEntry struct {
	Secret string // base32 encoded secret
}

// Password Entry
type PasswordEntry struct {
	Username string
	Password string
}

type Database struct {
	TotpAccounts map[string]TotpEntry
	Passwords    map[string]PasswordEntry
}

func NewDatabase() *Database {
	return &Database{
		TotpAccounts: make(map[string]TotpEntry),
		Passwords:    make(map[string]PasswordEntry),
	}
}
