# Security Baseline（監査用の要点）
- OWASP Top 10:2025 をリスク分類として使用
- OWASP ASVS v5 を受入基準として採用（推奨：L2）
- CI で SAST/SCA/SBOM/DAST を必須化し、証跡（artifact）を保存する

※ 実案件では ASVS の採用レベルと対象範囲を明記してください。

- Container Scanning：Trivy（FS/イメージ）
- Secret Detection：Gitleaks（SARIF）
