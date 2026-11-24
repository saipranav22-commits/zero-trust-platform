# ─── Build Stage ──────────────────────────────────────────────
FROM maven:3.9.8-eclipse-temurin-21-alpine AS build
WORKDIR /app

# Copy only pom.xml first to cache Maven dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -q

# Copy source and build
COPY src ./src
RUN mvn package -DskipTests -q

# ─── Runtime Stage ────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine AS runtime
WORKDIR /app

# Create non-root user for security
RUN addgroup -S ztapp && adduser -S ztapp -G ztapp

# Copy built artifact
COPY --from=build /app/target/*.jar app.jar
RUN chown ztapp:ztapp app.jar

USER ztapp

EXPOSE 8080

# JVM tuning for constrained containers (Render 512 MB Free Tier)
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:+UseSerialGC", \
  "-Xms160m", \
  "-Xmx256m", \
  "-XX:MaxMetaspaceSize=128m", \
  "-XX:ReservedCodeCacheSize=48m", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
