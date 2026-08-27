# Multi-stage build for eSign API
FROM maven:3.9.6-eclipse-temurin-21 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

# Install required packages
RUN apk add --no-cache \
    bash \
    curl \
    tzdata \
    && cp /usr/share/zoneinfo/Asia/Kolkata /etc/localtime \
    && echo "Asia/Kolkata" > /etc/timezone

# Create non-root user
RUN addgroup -g 1000 -S esign && \
    adduser -u 1000 -S esign -G esign

WORKDIR /app

# Copy built jar
COPY --from=builder /app/target/esign-api-3.3.0.jar app.jar

# Create directories
RUN mkdir -p /app/logs /app/keystore /app/certificates && \
    chown -R esign:esign /app

USER esign

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# Expose ports
EXPOSE 8080 8443

# JVM options
ENV JAVA_OPTS="-Xms512m -Xmx1024m -XX:+UseG1GC -XX:MaxGCPauseMillis=200"

# Run application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]