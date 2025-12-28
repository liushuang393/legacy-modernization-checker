/**
 * Prototype Pollution 脆弱性テスト用ファイル
 * 
 * 検出対象: Semgrep (カスタムルール)
 * 脆弱性: CWE-1321 Prototype Pollution
 */

// 脆弱性1: 危険なオブジェクトマージ
function mergeObjects(target: any, source: any): any {
    for (const key in source) {
        // NG: __proto__ や constructor を含むキーをそのまま代入
        target[key] = source[key];
    }
    return target;
}

// 脆弱性2: 再帰的マージによるPrototype Pollution
function deepMerge(target: any, source: any): any {
    for (const key of Object.keys(source)) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) {
                target[key] = {};
            }
            // NG: 再帰的マージで prototype chain を汚染可能
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 脆弱性3: ブラケット記法でのプロパティ設定
function setProperty(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
        // NG: __proto__ へのアクセスを許可
        if (!current[keys[i]]) {
            current[keys[i]] = {};
        }
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;
}

// 安全な実装例（参考）
function mergeObjectsSafe(target: any, source: any): any {
    for (const key in source) {
        // OK: 危険なキーをスキップ
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
        }
    }
    return target;
}

export { mergeObjects, deepMerge, setProperty, mergeObjectsSafe };

