//go:build darwin && cgo

//nolint:testpackage // Exercise the native plist parser without creating users or sessions.
package guestuser

import "testing"

func TestConsolePlistSessionPresenceAndReadiness(t *testing.T) {
	const target = `<dict><key>kCGSSessionUserIDKey</key><integer>20000</integer>`
	const onConsole = `<key>kCGSSessionOnConsoleKey</key><true/>`
	const background = `<key>kCGSSessionOnConsoleKey</key><false/>`
	const unlocked = `<key>CGSSessionScreenIsLocked</key><false/>`
	const locked = `<key>CGSSessionScreenIsLocked</key><true/>`
	const rows = `<dict><key>IOConsoleUsers</key><array>`
	const endRows = `</array></dict>`
	tests := []struct {
		name    string
		root    string
		present bool
		ready   bool
	}{
		{
			name:    "foreground with omitted lock flag",
			root:    `<array>` + rows + target + onConsole + `</dict>` + endRows + `</array>`,
			present: true, ready: true,
		},
		{
			name:    "foreground unlocked with dictionary root",
			root:    rows + target + onConsole + unlocked + `</dict>` + endRows,
			present: true, ready: true,
		},
		{
			name:    "background session",
			root:    rows + target + background + `</dict>` + endRows,
			present: true,
		},
		{
			name:    "locked foreground session",
			root:    rows + target + onConsole + locked + `</dict>` + endRows,
			present: true,
		},
		{
			name: "unrelated session",
			root: rows + `<dict><key>kCGSSessionUserIDKey</key><integer>501</integer></dict>` + endRows,
		},
		{name: "empty session array", root: rows + endRows},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(`<plist version="1.0">` + test.root + `</plist>`)
			present, ready, err := consolePlist(data, 20000)
			if err != nil || present != test.present || ready != test.ready {
				t.Fatalf("got present=%t ready=%t err=%v; want present=%t ready=%t",
					present, ready, err, test.present, test.ready)
			}
		})
	}
}

func TestConsolePlistRejectsInvalidOrDuplicateSessions(t *testing.T) {
	const target = `<dict><key>kCGSSessionUserIDKey</key><integer>20000</integer>`
	const onConsole = `<key>kCGSSessionOnConsoleKey</key><true/>`
	const rows = `<dict><key>IOConsoleUsers</key><array>`
	const endRows = `</array></dict>`
	const session = target + onConsole + `</dict>`
	tests := []struct {
		name string
		root string
	}{
		{name: "duplicate in one root", root: rows + session + session + endRows},
		{
			name: "duplicate across registry roots",
			root: `<array>` + rows + session + endRows + rows + session + endRows + `</array>`,
		},
		{name: "missing console flag", root: rows + target + `</dict>` + endRows},
		{
			name: "invalid console flag",
			root: rows + target + `<key>kCGSSessionOnConsoleKey</key><integer>1</integer></dict>` + endRows,
		},
		{
			name: "invalid lock flag",
			root: rows + target + onConsole + `<key>CGSSessionScreenIsLocked</key><string>false</string></dict>` + endRows,
		},
		{
			name: "invalid unrelated owner after valid target",
			root: rows + session + `<dict><key>kCGSSessionUserIDKey</key><string>501</string></dict>` + endRows,
		},
		{name: "missing owner", root: rows + `<dict/>` + endRows},
		{name: "missing session array", root: `<dict/>`},
		{name: "empty registry array", root: `<array/>`},
		{name: "duplicate empty session arrays", root: `<array>` + rows + endRows + rows + endRows + `</array>`},
		{name: "invalid session row", root: rows + `<string>invalid</string>` + endRows},
		{name: "invalid session array", root: `<dict><key>IOConsoleUsers</key><dict/></dict>`},
		{name: "invalid registry root", root: `<string>invalid</string>`},
		{name: "malformed plist", root: `<array>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(`<plist version="1.0">` + test.root + `</plist>`)
			present, ready, err := consolePlist(data, 20000)
			if err == nil || present || ready {
				t.Fatalf("got present=%t ready=%t err=%v; want an error and false outputs", present, ready, err)
			}
		})
	}
	t.Run("empty input", func(t *testing.T) {
		present, ready, err := consolePlist(nil, 20000)
		if err == nil || present || ready {
			t.Fatalf("got present=%t ready=%t err=%v; want an error and false outputs", present, ready, err)
		}
	})
}
