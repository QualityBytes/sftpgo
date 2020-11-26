// +build !nomssql

package dataprovider

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	// we import go-mssqldb here to be able to disable Microsoft SQL Server support using a build tag
	_ "github.com/denisenkom/go-mssqldb"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	mssqlUsersTableSQL = `CREATE TABLE [{{users}}] (
	[id] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY,
	[username] [varchar](255) NOT NULL UNIQUE,
	[password] [varchar](255) NULL,
	[public_keys] [text] NULL,
	[home_dir] [varchar](255) NOT NULL,
	[uid] [int] NOT NULL,
	[gid] [int] NOT NULL,
	[max_sessions] [int] NOT NULL,
	[quota_size] [bigint] NOT NULL,
	[quota_files] [int] NOT NULL,
	[permissions] [text] NOT NULL,
	[used_quota_size] [bigint] NOT NULL,
	[used_quota_files] [int] NOT NULL,
	[last_quota_update] [bigint] NOT NULL,
	[upload_bandwidth] [int] NOT NULL,
	[download_bandwidth] [int] NOT NULL,
	[expiration_date] [bigint] NOT NULL,
	[last_login] [bigint] NOT NULL,
	[status] [int] NOT NULL,
	[filters] [text] NULL,
	[filesystem] [text] NULL,
)`
	mssqlSchemaTableSQL = `CREATE TABLE [{{schema_version}}] ([id] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY, [version] [int] NOT NULL)`
	mssqlV2SQL          = `ALTER TABLE [{{users}}] ADD [virtual_folders] [text] NULL`
	mssqlV3SQL          = `ALTER TABLE [{{users}}] ALTER COLUMN [password] [text]`
	mssqlV4SQL          = `CREATE TABLE [{{folders}}] (
	[id] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY,
	[path] [varchar](512) NOT NULL UNIQUE,
	[used_quota_size] [bigint] NOT NULL,
	[used_quota_files] [int] NOT NULL,
	[last_quota_update] [bigint] NOT NULL
);
ALTER TABLE [{{users}}] ALTER COLUMN [home_dir] [varchar](512);
ALTER TABLE [{{users}}] DROP COLUMN [virtual_folders];
CREATE TABLE [{{folders_mapping}}] (
	[id] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY,
	[virtual_path] [varchar](512) NOT NULL,
	[quota_size] [bigint] NOT NULL,
	[quota_files] [int] NOT NULL,
	[folder_id] [int] NOT NULL,
	[user_id] [int] NOT NULL
);
ALTER TABLE [{{folders_mapping}}] ADD CONSTRAINT [unique_mapping] UNIQUE ([user_id], [folder_id]);
ALTER TABLE [{{folders_mapping}}] ADD CONSTRAINT [folders_mapping_folder_id_fk_folders_id] FOREIGN KEY ([folder_id]) REFERENCES [{{folders}}] ([id]) ON DELETE CASCADE ON UPDATE NO ACTION;
ALTER TABLE [{{folders_mapping}}] ADD CONSTRAINT [folders_mapping_user_id_fk_users_id] FOREIGN KEY ([user_id]) REFERENCES [{{users}}] ([id]) ON DELETE CASCADE ON UPDATE NO ACTION;
CREATE INDEX [folders_mapping_folder_id_idx] ON [{{folders_mapping}}] ([folder_id]);
CREATE INDEX [folders_mapping_user_id_idx] ON [{{folders_mapping}}] ([user_id])`
)

// MSSQLProvider auth provider for Microsoft SQL Server database
type MSSQLProvider struct {
	dbHandle *sql.DB
}

func init() {
	version.AddFeature("+mssql")
}

func initializeMSSQLProvider() error {
	var err error
	logSender = fmt.Sprintf("dataprovider_%v", MSSQLDataProviderName)
	dbHandle, err := sql.Open("sqlserver", getMSSQLConnectionString(false))
	if err == nil {
		providerLog(logger.LevelDebug, "MSSQL database handle created, connection string: %#v, pool size: %v",
			getMSSQLConnectionString(true), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		provider = MSSQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating MSSQL database handler, connection string: %#v, error: %v",
			getMSSQLConnectionString(true), err)
	}
	return err
}

func getMSSQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if len(config.ConnectionString) == 0 {
		password := config.Password
		if redactedPwd {
			password = "[redacted]"
		}
		connectionString = fmt.Sprintf("server=%v;port=%v;database=%v;user id=%v;password=%v;connection timeout=10;app name=sftpgo",
			config.Host, config.Port, config.Name, config.Username, password)
	} else {
		connectionString = config.ConnectionString
	}
	return connectionString
}

func (p MSSQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p MSSQLProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, p.dbHandle)
}

func (p MSSQLProvider) validateUserAndPubKey(username string, publicKey []byte) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p MSSQLProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID, p.dbHandle)
}

func (p MSSQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p MSSQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p MSSQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p MSSQLProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username, p.dbHandle)
}

func (p MSSQLProvider) addUser(user User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p MSSQLProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p MSSQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p MSSQLProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p MSSQLProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username, p.dbHandle)
}

func (p MSSQLProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p MSSQLProvider) getFolders(limit, offset int, order, folderPath string) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, folderPath, p.dbHandle)
}

func (p MSSQLProvider) getFolderByPath(mappedPath string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonCheckFolderExists(ctx, mappedPath, p.dbHandle)
}

func (p MSSQLProvider) addFolder(folder vfs.BaseVirtualFolder) error {
	return sqlCommonAddFolder(folder, p.dbHandle)
}

func (p MSSQLProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p MSSQLProvider) updateFolderQuota(mappedPath string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(mappedPath, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p MSSQLProvider) getUsedFolderQuota(mappedPath string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(mappedPath, p.dbHandle)
}

func (p MSSQLProvider) close() error {
	return p.dbHandle.Close()
}

func (p MSSQLProvider) reloadConfig() error {
	return nil
}

func (p MSSQLProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	sqlUsers := strings.Replace(mssqlUsersTableSQL, "{{users}}", sqlTableUsers, 1)
	tx, err := p.dbHandle.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(sqlUsers)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = tx.Exec(strings.Replace(mssqlSchemaTableSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = tx.Exec(strings.Replace(initialDBVersionSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}

func (p MSSQLProvider) migrateDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == sqlDatabaseVersion {
		providerLog(logger.LevelDebug, "sql database is up to date, current version: %v", dbVersion.Version)
		return ErrNoInitRequired
	}
	switch dbVersion.Version {
	case 1:
		return updateMSSQLDatabaseFromV1(p.dbHandle)
	case 2:
		return updateMSSQLDatabaseFromV2(p.dbHandle)
	case 3:
		return updateMSSQLDatabaseFromV3(p.dbHandle)
	case 4:
		return updateMSSQLDatabaseFromV4(p.dbHandle)
	default:
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

func updateMSSQLDatabaseFromV1(dbHandle *sql.DB) error {
	err := updateMSSQLDatabaseFrom1To2(dbHandle)
	if err != nil {
		return err
	}
	return updateMSSQLDatabaseFromV2(dbHandle)
}

func updateMSSQLDatabaseFromV2(dbHandle *sql.DB) error {
	err := updateMSSQLDatabaseFrom2To3(dbHandle)
	if err != nil {
		return err
	}
	return updateMSSQLDatabaseFromV3(dbHandle)
}

func updateMSSQLDatabaseFromV3(dbHandle *sql.DB) error {
	err := updateMSSQLDatabaseFrom3To4(dbHandle)
	if err != nil {
		return err
	}
	return updateMSSQLDatabaseFromV4(dbHandle)
}

func updateMSSQLDatabaseFromV4(dbHandle *sql.DB) error {
	return updateMSSQLDatabaseFrom4To5(dbHandle)
}

func updateMSSQLDatabaseFrom1To2(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 1 -> 2")
	providerLog(logger.LevelInfo, "updating database version: 1 -> 2")
	sql := strings.Replace(mssqlV2SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 2)
}

func updateMSSQLDatabaseFrom2To3(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 2 -> 3")
	providerLog(logger.LevelInfo, "updating database version: 2 -> 3")
	sql := strings.Replace(mssqlV3SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 3)
}

func updateMSSQLDatabaseFrom3To4(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom3To4(mssqlV4SQL, dbHandle)
}

func updateMSSQLDatabaseFrom4To5(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom4To5(dbHandle)
}

func mssqlGetDatabaseVersion(dbHandle *sql.DB, showInitWarn bool) (schemaVersion, error) {
	var result schemaVersion
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := fmt.Sprintf("SELECT TOP(1) [version] from [%v]", sqlTableSchemaVersion)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		if showInitWarn && strings.Contains(err.Error(), sqlTableSchemaVersion) {
			logger.WarnToConsole("database query error, did you forgot to run the \"initprovider\" command?")
		}
		return result, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx)
	err = row.Scan(&result.Version)
	return result, err
}
