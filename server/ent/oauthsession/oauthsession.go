// Code generated by ent, DO NOT EDIT.

package oauthsession

const (
	// Label holds the string label denoting the oauthsession type in the database.
	Label = "oauth_session"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldIssuer holds the string denoting the issuer field in the database.
	FieldIssuer = "issuer"
	// FieldSubject holds the string denoting the subject field in the database.
	FieldSubject = "subject"
	// FieldAudiences holds the string denoting the audiences field in the database.
	FieldAudiences = "audiences"
	// FieldExpiresAt holds the string denoting the expires_at field in the database.
	FieldExpiresAt = "expires_at"
	// FieldIssuedAt holds the string denoting the issued_at field in the database.
	FieldIssuedAt = "issued_at"
	// FieldRequestedAt holds the string denoting the requested_at field in the database.
	FieldRequestedAt = "requested_at"
	// FieldAuthTime holds the string denoting the auth_time field in the database.
	FieldAuthTime = "auth_time"
	// FieldRequestedScopes holds the string denoting the requested_scopes field in the database.
	FieldRequestedScopes = "requested_scopes"
	// FieldGrantedScopes holds the string denoting the granted_scopes field in the database.
	FieldGrantedScopes = "granted_scopes"
	// FieldRequestedAudiences holds the string denoting the requested_audiences field in the database.
	FieldRequestedAudiences = "requested_audiences"
	// FieldGrantedAudiences holds the string denoting the granted_audiences field in the database.
	FieldGrantedAudiences = "granted_audiences"
	// FieldRequest holds the string denoting the request field in the database.
	FieldRequest = "request"
	// FieldForm holds the string denoting the form field in the database.
	FieldForm = "form"
	// Table holds the table name of the oauthsession in the database.
	Table = "oauth_sessions"
)

// Columns holds all SQL columns for oauthsession fields.
var Columns = []string{
	FieldID,
	FieldIssuer,
	FieldSubject,
	FieldAudiences,
	FieldExpiresAt,
	FieldIssuedAt,
	FieldRequestedAt,
	FieldAuthTime,
	FieldRequestedScopes,
	FieldGrantedScopes,
	FieldRequestedAudiences,
	FieldGrantedAudiences,
	FieldRequest,
	FieldForm,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}