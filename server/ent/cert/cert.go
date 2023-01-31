// Code generated by ent, DO NOT EDIT.

package cert

const (
	// Label holds the string label denoting the cert type in the database.
	Label = "cert"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// Table holds the table name of the cert in the database.
	Table = "certs"
)

// Columns holds all SQL columns for cert fields.
var Columns = []string{
	FieldID,
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