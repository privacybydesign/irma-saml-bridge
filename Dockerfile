# Assets build stage
FROM node:25 AS assets-build
COPY . /app/
WORKDIR /app/assets/
RUN ./build.sh

# JAR build stage
FROM maven:3-openjdk-18 AS irma-saml-bridge-builder
COPY . /app/
COPY --from=assets-build /app/assets/dist /app/src/main/resources/static/assets
WORKDIR /app/
RUN mvn clean package test

FROM azul/zulu-openjdk:20-jre AS irma-saml-bridge
COPY --from=irma-saml-bridge-builder /app/target/*.jar irma-saml-bridge.jar
ENTRYPOINT ["java", "-jar", "/irma-saml-bridge.jar"]
