// Package config ...
package config

import (
	"encoding/json"
	"errors"
	"fmt"
)

type DBRecord struct {
	// Name is the name of the database
	Name string `json:"name"`
	// DefaultOwner is the role that receives ownership of objects
	// when a user is deleted. Typically the database/schema owner role.
	DefaultOwner string `json:"default_owner"`
}

// RDSDatabaseConfig describes a single RDS database instance where
// users should be provisioned alongside Identity Store.
type RDSDatabaseConfig struct {
	// Engine: "postgres" (mysql support can be added later)
	Engine string `json:"engine"`
	// Endpoint is the RDS instance hostname, e.g. "mydb.abc123.us-east-1.rds.amazonaws.com"
	Endpoint string `json:"endpoint"`
	// Port, e.g. 5432
	Port int        `json:"port"`
	DBs  []DBRecord `json:"dbs"`
	// Region overrides the global Region for IAM auth token generation.
	// If empty, the global cfg.Region is used.
	Region string `json:"region,omitempty"`
	// ServiceUser is the database role mapped to the IAM principal
	// that the Lambda (or local caller) assumes.
	ServiceUser string `json:"service_user"`
}

// Config ...
type Config struct {
	rdsDatabases []RDSDatabaseConfig
	// Verbose toggles the verbosity
	Debug bool
	// LogLevel is the level with with to log for this config
	LogLevel string `mapstructure:"log_level"`
	// LogFormat is the format that is used for logging
	LogFormat string `mapstructure:"log_format"`
	// GoogleCredentials ...
	GoogleCredentials string `mapstructure:"google_credentials"`
	// GoogleAdmin ...
	GoogleAdmin string `mapstructure:"google_admin"`
	// UserMatch ...
	UserMatch string `mapstructure:"user_match"`
	// GroupFilter ...
	GroupMatch string `mapstructure:"group_match"`
	// SCIMEndpoint ....
	SCIMEndpoint string `mapstructure:"scim_endpoint"`
	// SCIMAccessToken ...
	SCIMAccessToken string `mapstructure:"scim_access_token"`
	// IsLambda ...
	IsLambda bool
	// IsLambdaRunningInCodePipeline ...
	IsLambdaRunningInCodePipeline bool
	// Ignore users ...
	IgnoreUsers []string `mapstructure:"ignore_users"`
	// Ignore groups ...
	IgnoreGroups []string `mapstructure:"ignore_groups"`
	// Include groups ...
	IncludeGroups []string `mapstructure:"include_groups"`
	// SyncMethod allow to defined the sync method used to get the user and groups from Google Workspace
	SyncMethod string `mapstructure:"sync_method"`
	// Region is the region that the identity store exists on
	Region string `mapstructure:"region"`
	// IdentityStoreID is the ID of the identity store
	IdentityStoreID string `mapstructure:"identity_store_id"`
	// Precaching queries as a comma separated list of query strings
	PrecacheOrgUnits []string
	// DryRun flag, when set to true, no change will be made in the Identity Store
	DryRun bool
	// sync suspended user, if true suspended user and their group memberships are sync'd into IAM Identity Center
	SyncSuspended bool
	// User filter string
	UserFilter string
	// AWSProfile selects a named profile from ~/.aws/config + ~/.aws/credentials.
	// Useful for local debugging; ignored when running in Lambda.
	AWSProfile string `mapstructure:"aws_profile"`
	// RDSDatabasesJSON is the raw JSON string holding []RDSDatabaseConfig.
	RDSDatabasesJSON string `mapstructure:"rds_databases"`
	// IAMDBName is the name of the database that is being used for IAM authentication into rds
	IAMDBName string `mapstructure:"iam_db_name"`
}

const (
	// DefaultLogLevel is the default logging level.
	DefaultLogLevel = "info"
	// DefaultLogFormat is the default format of the logger
	DefaultLogFormat = "text"
	// DefaultDebug is the default debug status.
	DefaultDebug = false
	// DefaultGoogleCredentials is the default credentials path
	DefaultGoogleCredentials = "credentials.json"
	// DefaultSyncMethod is the default sync method to use.
	DefaultSyncMethod = "groups"
	// DefaultPrecacheOrgUnits
	DefaultPrecacheOrgUnits = "/"
)

// New returns a new Config
func New() *Config {
	return &Config{
		Debug:             DefaultDebug,
		LogLevel:          DefaultLogLevel,
		LogFormat:         DefaultLogFormat,
		SyncMethod:        DefaultSyncMethod,
		GoogleCredentials: DefaultGoogleCredentials,
	}
}

func (c *Config) GetRdsDatabases() ([]RDSDatabaseConfig, error) {
	if c.rdsDatabases == nil && c.RDSDatabasesJSON != "" {
		if err := c.parseRDSDatabases(); err != nil {
			return nil, err
		}
	}
	return c.rdsDatabases, nil
}

// parseRDSDatabases parses RDSDatabasesJSON into rdsDatabases.
// Call this after config is fully loaded.
func (c *Config) parseRDSDatabases() error {
	if c.RDSDatabasesJSON == "" {
		c.rdsDatabases = nil
		return nil
	}
	var dbs []RDSDatabaseConfig
	if err := json.Unmarshal([]byte(c.RDSDatabasesJSON), &dbs); err != nil {
		return fmt.Errorf("failed to parse rds_databases JSON: %w", err)
	}
	for i := range dbs {
		if dbs[i].Region == "" {
			dbs[i].Region = c.Region
		}
	}
	c.rdsDatabases = dbs
	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.GoogleAdmin == "" {
		return errors.New("google admin email is required")
	}

	if c.SCIMEndpoint == "" {
		return errors.New("SCIM endpoint is required")
	}

	if c.SCIMAccessToken == "" {
		return errors.New("SCIM access token is required")
	}

	if c.Region == "" {
		return errors.New("AWS region is required")
	}

	if c.IdentityStoreID == "" {
		return errors.New("identity store ID is required")
	}

	if c.SyncMethod != "groups" && c.SyncMethod != "users_groups" {
		return errors.New("sync method must be either 'groups' or 'users_groups'")
	}

	rdsDatabases, err := c.GetRdsDatabases()
	if err != nil {
		return err
	}

	for i, db := range rdsDatabases {
		if db.Engine != "postgres" {
			return fmt.Errorf("rds_databases[%d]: unsupported engine %q (only \"postgres\" is supported)", i, db.Engine)
		}
		if db.Endpoint == "" {
			return fmt.Errorf("rds_databases[%d]: endpoint is required", i)
		}
		if db.Port == 0 {
			return fmt.Errorf("rds_databases[%d]: port is required", i)
		}
		if len(db.DBs) == 0 {
			return fmt.Errorf("rds_databases[%d]: dbs array is required", i)
		}
		if db.ServiceUser == "" {
			return fmt.Errorf("rds_databases[%d]: service_user is required", i)
		}
	}

	return nil
}
