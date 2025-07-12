package database

import "strings"

type sqlColumn struct {
	Name                    string
	Type                    sqlDataType
	AutoIncrementPrimaryKey bool
	PrimaryKey              bool
	Unique                  bool
	NotNull                 bool
	Default                 string
}

type sqlDataType interface {
	SQL(kind int) string
}

type sqlInteger struct{}
type sqlText struct{}
type sqlBlob struct{}
type sqlTimestamp struct{}

func (c sqlInteger) SQL(kind int) string {
	switch kind {
	case sqlite:
		return "INTEGER"
	case postgres:
		return "INTEGER"
	case mysql:
		return "INT"
	}

	panic("unknown kind")
}

func (c sqlText) SQL(kind int) string {
	return "TEXT"
}

func (c sqlBlob) SQL(kind int) string {
	switch kind {
	case sqlite:
		return "BLOB"
	case postgres:
		return "BYTEA"
	case mysql:
		return "BLOB"
	}

	panic("unknown kind")
}

func (c sqlTimestamp) SQL(kind int) string {
	return "TIMESTAMP"
}

func (c sqlColumn) SQL(kind int) string {
	var parts []string

	if c.AutoIncrementPrimaryKey {
		switch kind {
		case sqlite:
			parts = append(parts, []string{c.Name, sqlInteger{}.SQL(kind), "PRIMARY KEY", "AUTOINCREMENT"}...)
		case postgres:
			parts = append(parts, []string{c.Name, "SERIAL"}...)
		case mysql:
			parts = append(parts, []string{c.Name, sqlInteger{}.SQL(kind), "PRIMARY KEY", "AUTO_INCREMENT"}...)
		}
	} else {
		parts = append(parts, []string{c.Name, c.Type.SQL(kind)}...)

		if c.PrimaryKey {
			parts = append(parts, "PRIMARY KEY")
		}
		if c.NotNull {
			parts = append(parts, "NOT NULL")
		}
		if c.Unique {
			parts = append(parts, "UNIQUE")
		}
		if c.Default != "" {
			parts = append(parts, "DEFAULT", c.Default)
		}
	}

	return strings.Join(parts, " ")
}

type sqlForeignKey struct {
	Column          string
	References      string
	OnDeleteCascade bool
}

type sqlTable struct {
	name              string
	columns           []sqlColumn
	primaryKeyColumns []string
	foreignKeys       []sqlForeignKey
}

func createSQLTable(name string) sqlTable {
	return sqlTable{
		name: name,
	}
}

func (t sqlTable) WithColumn(col sqlColumn) sqlTable {
	t.columns = append(t.columns, col)
	return t
}

func (t sqlTable) WithAutoincrementPrimaryKeyColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlInteger{}, AutoIncrementPrimaryKey: true})
	return t
}

func (t sqlTable) WithNonNullUniqueTextColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, NotNull: true, Unique: true})
	return t
}

func (t sqlTable) WithTextColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}})
	return t
}

func (t sqlTable) WithPrimaryKeyTextColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, PrimaryKey: true})
	return t
}

func (t sqlTable) WithNonNullTextColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, NotNull: true})
	return t
}

func (t sqlTable) WithNonNullBlobColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlBlob{}, NotNull: true})
	return t
}

func (t sqlTable) WithTimestampDefaultCurrentTimeColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlTimestamp{}, Default: "CURRENT_TIMESTAMP"})
	return t
}

func (t sqlTable) WithPrimaryKey(columns ...string) sqlTable {
	t.primaryKeyColumns = columns
	return t
}

func (t sqlTable) WithForeignKey(column string, references string) sqlTable {
	t.foreignKeys = append(t.foreignKeys, sqlForeignKey{
		Column:     column,
		References: references,
	})
	return t
}

func (t sqlTable) WithForeignKeyOnDeleteCascade(column string, references string) sqlTable {
	t.foreignKeys = append(t.foreignKeys, sqlForeignKey{
		Column:          column,
		References:      references,
		OnDeleteCascade: true,
	})
	return t
}

func (t sqlTable) SQL(kind int) string {
	c := make([]string, len(t.columns))
	for i := range t.columns {
		c[i] = t.columns[i].SQL(kind)
	}

	if len(t.primaryKeyColumns) > 0 {
		c = append(c, "PRIMARY KEY ("+strings.Join(t.primaryKeyColumns, ", ")+")")
	}

	for _, fk := range t.foreignKeys {
		f := "FOREIGN KEY (" + fk.Column + ") REFERENCES " + fk.References
		if fk.OnDeleteCascade {
			f += " ON DELETE CASCADE"
		}

		c = append(c, f)
	}

	return `CREATE TABLE IF NOT EXISTS ` + t.name + ` (
			` + strings.Join(c, ",\n") + `);`
}
