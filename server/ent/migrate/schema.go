// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// AccessRequestsColumns holds the columns for the "access_requests" table.
	AccessRequestsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "requested_scopes", Type: field.TypeJSON},
		{Name: "granted_scopes", Type: field.TypeJSON},
		{Name: "requested_audiences", Type: field.TypeJSON},
		{Name: "granted_audiences", Type: field.TypeJSON},
		{Name: "request", Type: field.TypeString},
		{Name: "form", Type: field.TypeString},
		{Name: "active", Type: field.TypeBool},
	}
	// AccessRequestsTable holds the schema information for the "access_requests" table.
	AccessRequestsTable = &schema.Table{
		Name:       "access_requests",
		Columns:    AccessRequestsColumns,
		PrimaryKey: []*schema.Column{AccessRequestsColumns[0]},
	}
	// CertsColumns holds the columns for the "certs" table.
	CertsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
	}
	// CertsTable holds the schema information for the "certs" table.
	CertsTable = &schema.Table{
		Name:       "certs",
		Columns:    CertsColumns,
		PrimaryKey: []*schema.Column{CertsColumns[0]},
	}
	// OidcAuthCodesColumns holds the columns for the "oidc_auth_codes" table.
	OidcAuthCodesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "authorization_code", Type: field.TypeString},
		{Name: "oidc_auth_code_access_request", Type: field.TypeInt, Nullable: true},
		{Name: "oidc_auth_code_session", Type: field.TypeInt, Nullable: true},
	}
	// OidcAuthCodesTable holds the schema information for the "oidc_auth_codes" table.
	OidcAuthCodesTable = &schema.Table{
		Name:       "oidc_auth_codes",
		Columns:    OidcAuthCodesColumns,
		PrimaryKey: []*schema.Column{OidcAuthCodesColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "oidc_auth_codes_access_requests_access_request",
				Columns:    []*schema.Column{OidcAuthCodesColumns[2]},
				RefColumns: []*schema.Column{AccessRequestsColumns[0]},
				OnDelete:   schema.SetNull,
			},
			{
				Symbol:     "oidc_auth_codes_oidc_sessions_session",
				Columns:    []*schema.Column{OidcAuthCodesColumns[3]},
				RefColumns: []*schema.Column{OidcSessionsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// OidcClientsColumns holds the columns for the "oidc_clients" table.
	OidcClientsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "client_id", Type: field.TypeString},
		{Name: "secret", Type: field.TypeString},
		{Name: "redirect_uris", Type: field.TypeJSON},
		{Name: "response_types", Type: field.TypeJSON},
		{Name: "grant_types", Type: field.TypeJSON},
		{Name: "scopes", Type: field.TypeJSON},
	}
	// OidcClientsTable holds the schema information for the "oidc_clients" table.
	OidcClientsTable = &schema.Table{
		Name:       "oidc_clients",
		Columns:    OidcClientsColumns,
		PrimaryKey: []*schema.Column{OidcClientsColumns[0]},
	}
	// OidcSessionsColumns holds the columns for the "oidc_sessions" table.
	OidcSessionsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "issuer", Type: field.TypeString},
		{Name: "subject", Type: field.TypeString},
		{Name: "audiences", Type: field.TypeJSON},
		{Name: "expires_at", Type: field.TypeTime},
		{Name: "issued_at", Type: field.TypeTime},
		{Name: "requested_at", Type: field.TypeTime},
		{Name: "auth_time", Type: field.TypeTime},
	}
	// OidcSessionsTable holds the schema information for the "oidc_sessions" table.
	OidcSessionsTable = &schema.Table{
		Name:       "oidc_sessions",
		Columns:    OidcSessionsColumns,
		PrimaryKey: []*schema.Column{OidcSessionsColumns[0]},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "name", Type: field.TypeString, Size: 25},
		{Name: "oauth_id", Type: field.TypeString, Unique: true},
		{Name: "session_token", Type: field.TypeString, Unique: true, Size: 1000},
		{Name: "is_activated", Type: field.TypeBool, Default: false},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		AccessRequestsTable,
		CertsTable,
		OidcAuthCodesTable,
		OidcClientsTable,
		OidcSessionsTable,
		UsersTable,
	}
)

func init() {
	OidcAuthCodesTable.ForeignKeys[0].RefTable = AccessRequestsTable
	OidcAuthCodesTable.ForeignKeys[1].RefTable = OidcSessionsTable
}
