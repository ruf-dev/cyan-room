package app

import (
	"context"

	"go.redsock.ru/rerrors"
	"golang.org/x/sync/errgroup"

	"go.redsock.ru/ruf/cyan-room/internal/server"
)

type Custom struct {
	server *server.Server
}

func (c *Custom) Init(a *App) (err error) {
	c.server, err = server.New(a.Cfg)
	if err != nil {
		return rerrors.Wrap(err, "")
	}

	return nil
}

func (c *Custom) Start(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(c.server.Start)

	err := eg.Wait()
	if err != nil {
		return rerrors.Wrap(err)
	}

	return nil
}

func (c *Custom) Stop() error {
	return nil
}
