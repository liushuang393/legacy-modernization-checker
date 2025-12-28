/**
 * ============================================================================
 * 【警告】このファイルは意図的に脆弱なコードを含むサンプルです
 * セキュリティスキャンのテスト用であり、本番環境では使用しないでください。
 * ============================================================================
 * 
 * OWASP Top 10:2025 に対応する脆弱性サンプル
 * Semgrep によって検出されることを確認するためのコードです。
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { exec } from 'child_process';

// =============================================================================
// A01:2025 - Broken Access Control（アクセス制御の不備）
// =============================================================================

/**
 * 【脆弱】オープンリダイレクト
 * ユーザー入力をそのままリダイレクト先に使用
 */
function vulnerableRedirect(req: any, res: any): void {
  const redirectUrl = req.query.url;
  // 危険: ユーザー入力を検証せずにリダイレクト
  res.redirect(redirectUrl);
}

// =============================================================================
// A02:2025 - Cryptographic Failures（暗号化の失敗）
// =============================================================================

/**
 * 【脆弱】弱いハッシュアルゴリズム
 * MD5/SHA1 は衝突攻撃に脆弱
 */
function vulnerableHash(password: string): string {
  // 危険: MD5は脆弱
  return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * 【脆弱】不安全な乱数生成
 * Math.random() は予測可能
 */
function vulnerableTokenGeneration(): string {
  // 危険: セキュリティ用途には不適切
  return Math.random().toString(36).substring(2);
}

// =============================================================================
// A03:2025 - Injection（インジェクション）
// =============================================================================

/**
 * 【脆弱】eval() 使用
 * 任意コード実行のリスク
 */
function vulnerableEval(userInput: string): any {
  // 危険: 任意のコードが実行される
  return eval(userInput);
}

/**
 * 【脆弱】innerHTML による XSS
 */
function vulnerableXss(element: HTMLElement, userContent: string): void {
  // 危険: XSS攻撃が可能
  element.innerHTML = userContent;
}

/**
 * 【脆弱】SQLインジェクション
 * 文字列連結によるクエリ構築
 */
async function vulnerableSqlQuery(db: any, userId: string): Promise<any> {
  // 危険: SQLインジェクション
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  return db.query(query);
}

/**
 * 【脆弱】コマンドインジェクション
 */
function vulnerableCommandExecution(userInput: string): void {
  // 危険: シェルインジェクション
  exec(`ls -la ${userInput}`);
}

/**
 * 【脆弱】パストラバーサル
 */
function vulnerableFileRead(userPath: string): string {
  // 危険: ディレクトリトラバーサル
  return fs.readFileSync(userPath, 'utf-8');
}

// =============================================================================
// A05:2025 - Security Misconfiguration（セキュリティ設定ミス）
// =============================================================================

/**
 * 【脆弱】ハードコードされた認証情報
 */
const API_KEY = "sk-1234567890abcdef";
const password = "SuperSecretPassword123!";
const secret = "my-jwt-secret-key";

// =============================================================================
// A07:2025 - Identification and Authentication Failures（認証の失敗）
// =============================================================================

/**
 * 【脆弱】JWT検証なし
 */
function vulnerableJwtDecode(token: string): any {
  const jwt = require('jsonwebtoken');
  // 危険: 署名検証なしでデコード
  return jwt.decode(token);
}

// =============================================================================
// A09:2025 - Security Logging and Monitoring Failures（ログ・監視の失敗）
// =============================================================================

/**
 * 【脆弱】機密情報のログ出力
 */
function vulnerableLogging(user: { password: string; token: string }): void {
  // 危険: パスワードがログに出力される
  console.log("User password:", user.password);
  console.log("User token:", user.token);
}

// =============================================================================
// A10:2025 - Server-Side Request Forgery (SSRF)
// =============================================================================

/**
 * 【脆弱】SSRF
 * ユーザー入力をそのままURLに使用
 */
async function vulnerableSsrf(userUrl: string): Promise<any> {
  // 危険: 内部ネットワークへのアクセスが可能
  return fetch(userUrl);
}

// =============================================================================
// エクスポート（テスト用）
// =============================================================================
export {
  vulnerableRedirect,
  vulnerableHash,
  vulnerableTokenGeneration,
  vulnerableEval,
  vulnerableXss,
  vulnerableSqlQuery,
  vulnerableCommandExecution,
  vulnerableFileRead,
  vulnerableJwtDecode,
  vulnerableLogging,
  vulnerableSsrf,
};

