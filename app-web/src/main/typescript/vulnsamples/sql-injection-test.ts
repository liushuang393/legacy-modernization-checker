/**
 * SQL Injection 脆弱性テスト用ファイル
 * 
 * 検出対象: Semgrep (p/typescript, カスタムルール)
 * 脆弱性: CWE-89 SQL Injection
 */

interface Database {
    query(sql: string): Promise<any[]>;
    execute(sql: string, params?: any[]): Promise<any>;
}

// 脆弱性1: 文字列連結によるSQL Injection
async function getUserByName(db: Database, name: string): Promise<any> {
    // NG: 文字列連結でSQLを構築
    const sql = "SELECT * FROM users WHERE name = '" + name + "'";
    return await db.query(sql);
}

// 脆弱性2: テンプレートリテラルによるSQL Injection  
async function searchProducts(db: Database, keyword: string, category: string): Promise<any[]> {
    // NG: テンプレートリテラルで直接埋め込み
    const sql = `SELECT * FROM products 
                 WHERE name LIKE '%${keyword}%' 
                 AND category = '${category}'`;
    return await db.query(sql);
}

// 脆弱性3: 動的テーブル名（SQL Injection）
async function getTableData(db: Database, tableName: string): Promise<any[]> {
    // NG: テーブル名を直接埋め込み
    const sql = `SELECT * FROM ${tableName}`;
    return await db.query(sql);
}

// 安全な実装例（参考）
async function getUserByNameSafe(db: Database, name: string): Promise<any> {
    // OK: パラメータ化クエリを使用
    const sql = "SELECT * FROM users WHERE name = ?";
    return await db.execute(sql, [name]);
}

export { getUserByName, searchProducts, getTableData, getUserByNameSafe };

