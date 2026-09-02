FROM gradle:9.7.1-jdk21 AS build
WORKDIR /workspace
COPY settings.gradle build.gradle gradle.properties gradlew ./
COPY gradle ./gradle
COPY src ./src
RUN ./gradlew --no-daemon clean bootJar

FROM eclipse-temurin:21-jre-jammy
RUN useradd --system --uid 10001 --create-home finsec
USER finsec
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
