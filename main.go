package main

import (
	"context"
	"log"
	"os"

	"att-air-cli/gateway"

	"github.com/sirupsen/logrus"
	altsrc "github.com/urfave/cli-altsrc/v3"
	toml "github.com/urfave/cli-altsrc/v3/toml"
	"github.com/urfave/cli/v3"
)

func main() {
	var gatewayURL string
	var debug bool
	var trace bool
	var configFile string
	var gw *gateway.GatewayClient

	configSource := altsrc.NewStringPtrSourcer(&configFile)

	loginFlags := []cli.Flag{
		&cli.StringFlag{
			Name:     "password",
			Usage:    "Login password",
			Sources:  cli.NewValueSourceChain(toml.TOML("login.password", configSource)),
			Required: true,
		},
	}

	app := &cli.Command{
		Name:  "AT&T Air Gateway CLI",
		Usage: "Login to the router or check compatibility",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "use the specified TOML configuration file",
				Destination: &configFile,
				TakesFile:   true,
			},
			&cli.StringFlag{
				Name:        "url",
				Usage:       "gateway base URL",
				Value:       "https://192.168.1.254",
				Sources:     cli.NewValueSourceChain(toml.TOML("gateway.url", configSource)),
				Destination: &gatewayURL,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Aliases:     []string{"d"},
				Usage:       "enable debug mode",
				Value:       false,
				Destination: &debug,
			},
			&cli.BoolFlag{
				Name:        "trace",
				Usage:       "enable trace mode",
				Value:       false,
				Destination: &trace,
			},
		},
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			gw = gateway.NewGatewayClient(gatewayURL)
			if trace {
				logrus.SetLevel(logrus.TraceLevel)
				gw.Debug()
			} else if debug {
				logrus.SetLevel(logrus.DebugLevel)
				gw.Debug()
			}
			return nil, nil
		},
		Commands: []*cli.Command{
			{
				Name:  "compat",
				Usage: "Check gateway compatibility",
				Action: func(appCtx context.Context, c *cli.Command) error {
					return gw.CheckCompatibility()
				},
			},
			{
				Name:  "login",
				Usage: "Login to the gateway and exit",
				Flags: loginFlags,
				Action: func(appCtx context.Context, c *cli.Command) error {
					password := c.String("password")
					return gw.Login(password)
				},
			},
			{
				Name:  "reset-wan",
				Usage: "Reset WAN connection",
				Flags: loginFlags,
				Action: func(appCtx context.Context, c *cli.Command) error {
					password := c.String("password")
					err := gw.Login(password)
					if err != nil {
						return err
					}
					return gw.ResetWanConnection()
				},
			},
		},
	}

	err := app.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
