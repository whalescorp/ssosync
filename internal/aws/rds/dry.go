package rds

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// NewDryClient returns a Client that only logs intended operations.
func NewDryClient() Client {
	return &dryClient{}
}

type dryClient struct{}

func (d *dryClient) SyncUsers(_ context.Context, wantedEmails []string) error {
	log.WithField("wanted_count", len(wantedEmails)).Warn("[dry-run] would sync RDS users")
	for _, email := range wantedEmails {
		log.WithField("email", email).Debug("[dry-run] wanted RDS user")
	}
	return nil
}
