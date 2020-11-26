// +build nomssql

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-mssql")
}

func initializeMSSQLProvider() error {
	return errors.New("Microsoft SQL Server disabled at build time")
}
