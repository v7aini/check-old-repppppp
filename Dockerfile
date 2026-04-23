# Build stage
FROM maven:3.8.4-openjdk-17-slim AS build
COPY . .
RUN mvn clean package -DskipTests

# Run stage
FROM openjdk:17-jdk-slim
COPY --from=build /target/*.jar app.jar
EXPOSE 9090
ENTRYPOINT ["java", "-jar", "/app.jar"]
