package adapter

import (
	"context"
	"io"

	"github.com/layou233/zbproxy/v3/config"
)

type Service interface {
	Start(ctx context.Context) error
	Reload(ctx context.Context, newConfig *config.Service) error
	UpdateRouter(router Router)
	// SetAuthSecret injects the root AuthSecret (normalized bytes held by the service).
	// Call before Start/Reload so the listen loop never races on an empty secret.
	SetAuthSecret(secret string)
	io.Closer
}
