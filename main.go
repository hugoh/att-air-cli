package main

import (
	"context"
	"log"
	"os"

	"att-air-cli/gateway"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

func main() {
	var gatewayURL string
	var debug bool
	var trace bool
	var gw *gateway.GatewayClient

	app := &cli.Command{
		Name:  "AT&T Air Gateway CLI",
		Usage: "Login to the router or check compatibility",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "url",
				Usage:       "Gateway base URL",
				Value:       "https://192.168.1.254",
				Destination: &gatewayURL,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Usage:       "Enable debug mode",
				Value:       false,
				Destination: &debug,
			},
			&cli.BoolFlag{
				Name:        "trace",
				Usage:       "Enable trace mode",
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Usage:    "Login password",
						Required: true,
					},
				},
				Action: func(appCtx context.Context, c *cli.Command) error {
					password := c.String("password")
					return gw.Login(password)
				},
			},
			{
				Name:  "reset-wan",
				Usage: "Reset WAN connection",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Usage:    "Login password",
						Required: true,
					},
				},
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
