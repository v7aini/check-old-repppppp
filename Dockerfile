# Build stage
FROM maven:3.9.6-eclipse-temurin-21-jammy AS build
COPY . .
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:21-jre-jammy
COPY --from=build /target/*.jar app.jar
EXPOSE 9090
ENTRYPOINT ["java", "-jar", "/app.jar"]
