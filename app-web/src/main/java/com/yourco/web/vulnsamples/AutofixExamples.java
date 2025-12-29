package com.yourco.web.vulnsamples;

/**
 * Semgrep Autofix 対応テストケース
 * 
 * これらの脆弱性は semgrep --autofix で自動修正可能
 * 検出: Semgrep カスタムルール (.semgrep.yml)
 */
public class AutofixExamples {

    /**
     * Autofix 1: String比較に == を使用
     * 修正: equals() に置換
     */
    public boolean compareStrings(String a, String b) {
        // NG: == で文字列比較 → equals() に自動修正可能
        if (a == b) {
            return true;
        }
        return a == "literal";  // これも NG
    }

    /**
     * Autofix 2: 空のcatchブロック
     * 修正: ログ出力を追加
     */
    public void emptyCatch() {
        try {
            riskyOperation();
        } catch (Exception e) {
            // NG: 空のcatchブロック → ログ出力を追加
        }
    }

    /**
     * Autofix 3: System.out.println 使用
     * 修正: Logger に置換
     */
    public void debugOutput(String message) {
        // NG: System.out.println → Logger.info() に自動修正可能
        System.out.println("Debug: " + message);
        System.err.println("Error: " + message);
    }

    /**
     * Autofix 4: 非推奨のDate API
     * 修正: java.time API に置換
     */
    public java.util.Date getCurrentDate() {
        // NG: new Date() → Instant.now() または LocalDateTime.now()
        return new java.util.Date();
    }

    /**
     * Autofix 5: StringBuffer → StringBuilder
     * シングルスレッド環境では StringBuilder が効率的
     */
    public String buildString() {
        // NG: StringBuffer → StringBuilder に自動修正可能
        StringBuffer sb = new StringBuffer();
        sb.append("Hello");
        sb.append(" ");
        sb.append("World");
        return sb.toString();
    }

    /**
     * Autofix 6: 未使用の変数
     */
    public void unusedVariables() {
        String unused = "This is never used";  // NG: 削除可能
        int count = 0;  // NG: 削除可能
        System.out.println("Hello");
    }

    /**
     * Autofix 7: リソースリーク
     * 修正: try-with-resources に置換
     */
    public void resourceLeak() throws Exception {
        // NG: try-with-resources を使用すべき
        java.io.FileInputStream fis = new java.io.FileInputStream("file.txt");
        int data = fis.read();
        fis.close();  // 例外発生時にcloseされない
    }

    /**
     * Autofix 8: 非効率な文字列連結
     * ループ内での + 演算子
     */
    public String inefficientConcat(String[] items) {
        String result = "";
        for (String item : items) {
            // NG: ループ内で文字列連結 → StringBuilder使用に修正
            result = result + item + ",";
        }
        return result;
    }

    /**
     * Autofix 9: == null と != null
     * 修正: Objects.isNull() / Objects.nonNull()
     */
    public void nullChecks(Object obj) {
        // NG: Objects.isNull(obj) に修正可能
        if (obj == null) {
            return;
        }
        // NG: Objects.nonNull(obj) に修正可能
        if (obj != null) {
            System.out.println(obj);
        }
    }

    /**
     * Autofix 10: ボクシング/アンボクシングの明示化
     */
    public void boxingIssues() {
        // NG: Integer.valueOf() を使用すべき
        Integer i = new Integer(42);
        // NG: Boolean.valueOf() を使用すべき  
        Boolean b = new Boolean(true);
    }

    private void riskyOperation() throws Exception {
        throw new Exception("Risky!");
    }
}

