# サンプル：app-web のコンテナ化（実案件ではベースイメージ方針/脆弱性対応を統一）
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY app-web/target/*.jar app-web.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app-web.jar"]
