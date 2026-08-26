use crate::technology::Database;

use crate::util;

pub fn detect_database(headers: &[(String, String)], body: Option<&str>) -> Option<Database> {
    if let Some(db) = detect_from_error_patterns(body) {
        return Some(db);
    }
    detect_from_headers(headers)
}

#[allow(clippy::too_many_lines)]
fn detect_from_error_patterns(body: Option<&str>) -> Option<Database> {
    let text = util::body_str(body);
    if text.is_empty() {
        return None;
    }
    let lower = text.to_lowercase();

    if lower.contains("you have an error in your sql syntax") {
        return Some(Database::MySQL);
    }
    if lower.contains("mysql") && (lower.contains("error") || lower.contains("syntax")) {
        return Some(Database::MySQL);
    }
    if lower.contains("mysqld") || lower.contains("mariadb") {
        return Some(Database::MySQL);
    }

    if lower.contains("postgresql") || lower.contains("postgres") {
        return Some(Database::PostgreSQL);
    }
    if lower.contains("pg_query") || lower.contains("pg_connect") {
        return Some(Database::PostgreSQL);
    }
    if lower.contains("psycopg2") || lower.contains("pq: ") {
        return Some(Database::PostgreSQL);
    }

    if lower.contains("sqlite3") || lower.contains("sqlite_") {
        return Some(Database::SQLite);
    }

    if lower.contains("microsoft sql server") || lower.contains("mssql") {
        return Some(Database::MsSql);
    }
    if lower.contains("sqlclient") || lower.contains("oledb") {
        return Some(Database::MsSql);
    }
    if lower.contains("sql server") && lower.contains("driver") {
        return Some(Database::MsSql);
    }

    if lower.contains("ora-0") || lower.contains("ora-1") || lower.contains("ora-2") {
        return Some(Database::Oracle);
    }
    if lower.contains("oracle") && lower.contains("database") {
        return Some(Database::Oracle);
    }

    if lower.contains("mongodb") || lower.contains("mongoose") {
        return Some(Database::MongoDB);
    }
    if lower.contains("bsonobj") || lower.contains("objectid(") {
        return Some(Database::MongoDB);
    }

    if lower.contains("redis") && (lower.contains("error") || lower.contains("connection refused"))
    {
        return Some(Database::Redis);
    }
    if lower.contains("redis::") || lower.contains("redis-server") {
        return Some(Database::Redis);
    }

    if lower.contains("cassandra") || lower.contains("cql_error") {
        return Some(Database::Cassandra);
    }

    None
}

fn detect_from_headers(headers: &[(String, String)]) -> Option<Database> {
    if util::header_contains(headers, "x-powered-by", "phpmyadmin") {
        return Some(Database::MySQL);
    }
    if util::header_contains(headers, "x-powered-by", "pgadmin") {
        return Some(Database::PostgreSQL);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn detect_mysql_syntax_error() {
        let b = Some("You have an error in your SQL syntax near 'SELECT * FROM'");
        assert!(matches!(detect_database(&[], b), Some(Database::MySQL)));
    }

    #[test]
    fn detect_mysql_generic() {
        let b = Some("MySQL Error: Connection refused");
        assert!(matches!(detect_database(&[], b), Some(Database::MySQL)));
    }

    #[test]
    fn detect_postgresql() {
        let b = Some("ERROR: relation \"users\" does not exist - PostgreSQL");
        assert!(matches!(
            detect_database(&[], b),
            Some(Database::PostgreSQL)
        ));
    }

    #[test]
    fn detect_postgresql_psycopg2() {
        let b = Some("psycopg2.OperationalError: FATAL: database does not exist");
        assert!(matches!(
            detect_database(&[], b),
            Some(Database::PostgreSQL)
        ));
    }

    #[test]
    fn detect_sqlite() {
        let b = Some("sqlite3.OperationalError: no such table: users");
        assert!(matches!(detect_database(&[], b), Some(Database::SQLite)));
    }

    #[test]
    fn detect_mssql() {
        let b = Some("Microsoft SQL Server Error: Incorrect syntax near keyword");
        assert!(matches!(detect_database(&[], b), Some(Database::MsSql)));
    }

    #[test]
    fn detect_oracle() {
        let b = Some("ORA-00942: table or view does not exist");
        assert!(matches!(detect_database(&[], b), Some(Database::Oracle)));
    }

    #[test]
    fn detect_mongodb() {
        let b = Some("MongoError: failed to connect to MongoDB server");
        assert!(matches!(detect_database(&[], b), Some(Database::MongoDB)));
    }

    #[test]
    fn detect_redis() {
        let b = Some("redis::ConnectionError: connection refused to redis-server");
        assert!(matches!(detect_database(&[], b), Some(Database::Redis)));
    }

    #[test]
    fn detect_cassandra() {
        let b = Some("cassandra.cluster.NoHostAvailable: unable to connect");
        assert!(matches!(detect_database(&[], b), Some(Database::Cassandra)));
    }

    #[test]
    fn detect_mysql_from_header() {
        let headers = h(&[("X-Powered-By", "phpMyAdmin")]);
        assert!(matches!(
            detect_database(&headers, None),
            Some(Database::MySQL)
        ));
    }

    #[test]
    fn no_database_detected() {
        let b = Some("<html><body>Normal page</body></html>");
        assert!(detect_database(&[], b).is_none());
    }
}
