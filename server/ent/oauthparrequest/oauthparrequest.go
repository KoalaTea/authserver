// Code generated by ent, DO NOT EDIT.

package oauthparrequest

const (
	// Label holds the string label denoting the oauthparrequest type in the database.
	Label = "oauth_par_request"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldRequest holds the string denoting the request field in the database.
	FieldRequest = "request"
	// Table holds the table name of the oauthparrequest in the database.
	Table = "oauth_par_requests"
)

// Columns holds all SQL columns for oauthparrequest fields.
var Columns = []string{
	FieldID,
	FieldRequest,
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
