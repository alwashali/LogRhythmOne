package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli"
)

var app = cli.NewApp()

func info() {
	app.Name = "Unified LogRhythm API"
	app.Usage = "Control multiple LogRhythm SIEMs from one API"
	app.Author = "@Ali_Alwashali"
}

func commands() {
	app.Commands = []cli.Command{
		{
			Name: "run",

			Usage: "Run Server",
			Action: func(c *cli.Context) {
				MuxServer()
			},
		},
		{
			Name: "user",

			Usage: "Add a new user account",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "username, u",
					Usage:    "Account username",
					Required: true,
				},

				&cli.StringFlag{
					Name:     "password, pw",
					Usage:    "Account Password",
					Required: true,
				},
				&cli.StringSliceFlag{
					Name:  "permission, p",
					Usage: "LogRhythm SIEMS allowed to be searched.",

					Value: &cli.StringSlice{"all"},
				},
			},
			Action: func(c *cli.Context) {
				create_user(c.String("username"), c.String("password"), c.StringSlice("permission"))

			},
		},
		{
			Name: "token",

			Usage: "Generate a new token",
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:  "days, d",
					Usage: "Number of days to use for token life time",
					Value: 365,
				},
				&cli.StringSliceFlag{
					Name:     "permission, p",
					Usage:    "LogRhythm SIEMS allowed to be searched. Use 'all' for all SIEMs",
					Required: true,
				},
			},
			Action: func(c *cli.Context) {

				token, err := generateAPIToken(c.StringSlice("permission"), c.Int("days"))
				if err != nil {
					log.Println(err)
				}

				fmt.Printf("\nToken Generated:\n%s\nLife time in days: %d", token, c.Int("days"))

			},
		},
		{
			Name: "join",

			Usage: "Join a new LogRhtyhm SIEM",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "name, n",
					Usage:    "LogRhythm Instance Name",
					Required: true,
				},

				&cli.StringFlag{
					Name:     "host, ip",
					Usage:    "LogRhythm IP Address or domain",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "token, t",
					Usage:    "LogRhythm Token",
					Required: true,
				},
			},
			Action: func(c *cli.Context) {
				add_Instance(c.String("name"), c.String("host"), c.String("token"))

			},
		},
	}
}

func main() {

	info()
	commands()

	err := app.Run(os.Args)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

}
