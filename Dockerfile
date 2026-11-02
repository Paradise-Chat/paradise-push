FROM clojure:temurin-21-tools-deps-alpine AS builder
WORKDIR /build
COPY deps.edn build.clj ./
RUN clojure -P && clojure -T:build clean
COPY src ./src
RUN clojure -T:build uber

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /build/target/paradise-push.jar /app/paradise-push.jar
RUN mkdir -p /app/configs /app/routes
ENV CONFIG_PATH=/app/configs/config.edn
EXPOSE 5000
ENTRYPOINT ["java", "-XX:+UseZGC", "-XX:+ZGenerational", "-jar", "/app/paradise-push.jar"]