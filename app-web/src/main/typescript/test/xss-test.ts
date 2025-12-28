/**
 * XSS 脆弱性テスト用ファイル
 * 
 * 検出対象: Semgrep (p/typescript, カスタムルール)
 * 脆弱性: CWE-79 Cross-site Scripting
 */

// 脆弱性1: innerHTML による DOM XSS
function displayUserMessage(message: string): void {
    const container = document.getElementById('message-container');
    if (container) {
        // NG: innerHTML に未サニタイズのユーザー入力
        container.innerHTML = `<div class="message">${message}</div>`;
    }
}

// 脆弱性2: document.write による XSS
function renderWelcome(username: string): void {
    // NG: document.write に未サニタイズの入力
    document.write(`<h1>Welcome, ${username}!</h1>`);
}

// 脆弱性3: eval による任意コード実行
function executeUserCode(code: string): any {
    // NG: eval でユーザー入力を実行
    return eval(code);
}

// 脆弱性4: outerHTML による DOM 操作
function replaceContent(element: HTMLElement, content: string): void {
    // NG: outerHTML に未検証の入力
    element.outerHTML = content;
}

// 安全な実装例（参考）
function displayUserMessageSafe(message: string): void {
    const container = document.getElementById('message-container');
    if (container) {
        // OK: textContent を使用（HTML として解釈されない）
        const div = document.createElement('div');
        div.className = 'message';
        div.textContent = message;
        container.appendChild(div);
    }
}

export { displayUserMessage, renderWelcome, executeUserCode, replaceContent, displayUserMessageSafe };

