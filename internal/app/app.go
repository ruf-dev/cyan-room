// Code generated by RedSock CLI. DO NOT EDIT.

package app

import (
	"context"
	"github.com/sirupsen/logrus"
	"go.redsock.ru/rerrors"
	"go.redsock.ru/toolbox"
	"go.redsock.ru/toolbox/closer"
	"golang.org/x/sync/errgroup"

	"go.redsock.ru/ruf/cyan-room/internal/config"
)

type App struct {
	Ctx  context.Context
	Stop func()
	Cfg  config.Config

	Custom Custom
}

func New() (app App, err error) {
	logrus.Println("starting app")

	err = app.InitConfig()
	if err != nil {
		return App{}, rerrors.Wrap(err, "error initializing config")
	}

	err = app.Custom.Init(&app)
	if err != nil {
		return App{}, rerrors.Wrap(err, "error initializing custom app properties")
	}

	return app, nil
}

func (a *App) Start() (err error) {
	var eg *errgroup.Group
	eg, a.Ctx = errgroup.WithContext(a.Ctx)

	eg.Go(func() error {
		return a.Custom.Start(a.Ctx)
	})
	closer.Add(a.Custom.Stop)

	interaptedC := func() chan struct{} {
		c := make(chan struct{})
		go func() {
			toolbox.WaitForInterrupt()
			close(c)
		}()

		return c
	}()

	errC := func() chan error {
		c := make(chan error)
		go func() {
			c <- eg.Wait()
			close(c)
			return
		}()
		return c
	}()

	select {
	case err := <-errC:
		logrus.Println("error during application startup: ", err)
	case <-interaptedC:
		logrus.Println("received interrupt signal")
	}
	logrus.Println("shutting down the app")

	err = closer.Close()
	if err != nil {
		return rerrors.Wrap(err, "error while shutting down application")
	}

	return nil
}
