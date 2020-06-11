package main

import (
	"os"
	"os/exec"

	"github.com/ProtonMail/go-autostart"
)

func setAutoStart(enable bool) {

	path, err := exec.LookPath(os.Args[0])
	if err != nil {
		return
	}

	app := &autostart.App{
		Name:        "invis",
		DisplayName: "http socks5 proxy",
		Exec:        []string{path, ""},
	}

	/*
		if enable != app.IsEnabled() {
			if enable {
				app.Enable()
			} else {
				app.Disable()
			}
		}
	*/

	app.Disable()
	if enable {
		app.Enable()
	}
}
