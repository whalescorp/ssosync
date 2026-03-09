package rds

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/awslabs/ssosync/internal/config"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

const pgRoleNameMaxLen = 63
const managedByComment = "managed-by:ssosync"
const ssosyncReadersRole = "ssosync_readers"

// Client manages database user provisioning across a set of RDS instances.
type Client interface {
	SyncUsers(ctx context.Context, wantedEmails []string) error
}

// NewClient returns a live Client that connects to every configured
// RDS instance using IAM auth and executes DDL statements.
func NewClient(awsCfg aws.Config, databases []config.RDSDatabaseConfig, iamDBName string) Client {
	return &client{awsCfg: awsCfg, databases: databases, iamDBName: iamDBName}
}

type client struct {
	awsCfg    aws.Config
	databases []config.RDSDatabaseConfig
	iamDBName string
}

func (c *client) SyncUsers(ctx context.Context, wantedEmails []string) error {
	if len(c.databases) == 0 {
		return nil
	}
	wantedSet := make(map[string]struct{}, len(wantedEmails))
	for _, e := range wantedEmails {
		if len(e) > pgRoleNameMaxLen {
			return fmt.Errorf("email %q exceeds PostgreSQL role name limit (%d bytes)", e, pgRoleNameMaxLen)
		}
		wantedSet[e] = struct{}{}
	}

	for _, dbInstance := range c.databases {
		dbNames := make([]string, len(dbInstance.DBs))
		for i, db := range dbInstance.DBs {
			dbNames[i] = db.Name
		}
		ll := log.WithFields(log.Fields{
			"rds_endpoint": dbInstance.Endpoint,
			"rds_dbnames":  dbNames,
		})
		ll.Info("syncing RDS users")

		if err := c.execOnDB(ctx, dbInstance, dbInstance.DBs[0].Name, func(conn *sql.DB) error {
			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("begin transaction for creating service and regular users: %w", err)
			}
			defer func() {
				if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
					ll.WithError(err).Error("failed to rollback transaction for creating service and regular users")
				}
			}()

			createServiceUsertTx := `
				DO $$
				BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM pg_roles WHERE rolname = '` + ssosyncReadersRole + `'
				) THEN
					CREATE GROUP ` + ssosyncReadersRole + ` NOLOGIN;
				END IF;
				END
				$$;	`
			if _, err := tx.ExecContext(ctx, createServiceUsertTx); err != nil {
				return fmt.Errorf("create service user: %w", err)
			}

			existing, err := getManagedUsers(ctx, tx)
			if err != nil {
				return err
			}

			toCreate, toDelete := diffUsers(wantedSet, existing)

			ll.WithFields(log.Fields{
				"existing": len(existing),
				"wanted":   len(wantedEmails),
				"create":   len(toCreate),
				"delete":   len(toDelete),
			}).Info("RDS user diff computed")

			for _, email := range toCreate {
				ul := ll.WithField("email", email)
				ul.Info("creating RDS user")
				quoted := pq.QuoteIdentifier(email)
				if _, err := tx.ExecContext(ctx, "CREATE USER "+quoted+" WITH LOGIN IN GROUP "+ssosyncReadersRole+", rds_iam"); err != nil {
					return fmt.Errorf("CREATE USER %q: %w", email, err)
				}
				// if _, err := tx.ExecContext(ctx, "GRANT rds_iam TO "+quoted); err != nil {
				// 	return fmt.Errorf("GRANT rds_iam TO %q: %w", email, err)
				// }
				if _, err := tx.ExecContext(ctx, "COMMENT ON ROLE "+quoted+" IS '"+managedByComment+"'"); err != nil {
					return fmt.Errorf("COMMENT ON ROLE %q: %w", email, err)
				}
			}
			for _, email := range toDelete {
				ul := ll.WithField("email", email)
				ul.Warn("deleting RDS user")
				quoted := pq.QuoteIdentifier(email)
				if _, err := tx.ExecContext(ctx, "DROP USER IF EXISTS "+quoted); err != nil {
					return fmt.Errorf("DROP USER %q: %w", email, err)
				}
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("committing transaction for creating service and regular users: %w", err)
			}
			return nil

		}); err != nil {
			ll.WithError(err).Error("failed to sync RDS users")
			return fmt.Errorf("rds %s/%s: sync users: %w", dbInstance.Endpoint, dbInstance.DBs[0].Name, err)
		}

		for _, db := range dbInstance.DBs {
			owner := pq.QuoteIdentifier(db.DefaultOwner)
			// FIXME: revoke privileges when database is being removed from the list of databases
			if err := c.execOnDB(ctx, dbInstance, db.Name, func(conn *sql.DB) error {
				tx, err := conn.BeginTx(ctx, nil)
				if err != nil {
					return fmt.Errorf("begin transaction for grant ssosync readers role: %w", err)
				}
				defer func() {
					if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
						ll.WithError(err).Error("failed to rollback transaction for grant ssosync readers role")
					}
				}()
				if _, err := tx.ExecContext(ctx, "GRANT USAGE ON SCHEMA public TO "+ssosyncReadersRole); err != nil {
					return fmt.Errorf("GRANT USAGE ON SCHEMA public TO "+ssosyncReadersRole+": %w", err)
				}
				if _, err := tx.ExecContext(ctx, "GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+ssosyncReadersRole); err != nil {
					return fmt.Errorf("GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+ssosyncReadersRole+": %w", err)
				}
				if _, err := tx.ExecContext(ctx, "ALTER DEFAULT PRIVILEGES FOR ROLE "+owner+" IN SCHEMA public GRANT SELECT ON TABLES TO "+ssosyncReadersRole); err != nil {
					return fmt.Errorf("ALTER DEFAULT PRIVILEGES FOR ROLE %q IN SCHEMA public GRANT SELECT ON TABLES TO %q: %w", owner, ssosyncReadersRole, err)
				}

				if err := tx.Commit(); err != nil {
					return fmt.Errorf("committing transaction for grant ssosync readers role: %w", err)
				}
				return nil
			}); err != nil {
				ll.WithError(err).Error("failed to grant ssosync readers role")
				return fmt.Errorf("rds %s/%s: grant ssosync readers role: %w", dbInstance.Endpoint, db.Name, err)
			}
		}
	}
	return nil
}

// getManagedUsers returns rolenames that were created by ssosync
// (identified by the "managed-by:ssosync" comment on the role).
// Roles with rds_iam but without this comment are left untouched.
func getManagedUsers(ctx context.Context, conn *sql.Tx) (map[string]struct{}, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT r.rolname
		FROM pg_roles r
		JOIN pg_shdescription d ON d.objoid = r.oid
			AND d.classoid = 'pg_authid'::regclass
			AND d.description = '`+managedByComment+`'
		WHERE r.rolcanlogin = true AND r.rolname != (SELECT CURRENT_USER)
	`)
	if err != nil {
		return nil, fmt.Errorf("query managed users: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.WithError(err).Error("failed to close rows")
		}
	}()

	result := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan rolname: %w", err)
		}
		result[name] = struct{}{}
	}
	return result, rows.Err()
}

// diffUsers returns lists of emails to create and delete.
func diffUsers(wanted map[string]struct{}, existing map[string]struct{}) (toCreate []string, toDelete []string) {
	for email := range wanted {
		if _, ok := existing[email]; !ok {
			toCreate = append(toCreate, email)
		}
	}
	for email := range existing {
		if _, ok := wanted[email]; !ok {
			toDelete = append(toDelete, email)
		}
	}
	return
}

// execOnDB executes a function on a given RDS database.
func (c *client) execOnDB(ctx context.Context, db config.RDSDatabaseConfig, dbname string, fn func(*sql.DB) error) error {
	region := db.Region
	if region == "" {
		region = c.awsCfg.Region
	}

	endpoint := net.JoinHostPort(db.Endpoint, strconv.Itoa(db.Port))
	if c.iamDBName != "" {
		endpoint = net.JoinHostPort(c.iamDBName, strconv.Itoa(db.Port))
	}

	token, err := auth.BuildAuthToken(ctx, endpoint, region, db.ServiceUser, c.awsCfg.Credentials)
	if err != nil {
		return fmt.Errorf("build IAM auth token: %w", err)
	}

	dsn := (&url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(db.ServiceUser, token),
		Host:   net.JoinHostPort(db.Endpoint, strconv.Itoa(db.Port)),
		Path:   dbname,
		RawQuery: url.Values{
			"sslmode":         []string{"require"},
			"connect_timeout": []string{"10"},
		}.Encode(),
	}).String()

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("connect to %s/%s: %w", db.Endpoint, dbname, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.WithError(err).Error("failed to close connection")
		}
	}()

	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("ping %s/%s: %w", db.Endpoint, dbname, err)
	}

	return fn(conn)
}
