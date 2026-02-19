FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace
COPY . /workspace
RUN chmod +x gradlew && ./gradlew :auth-server:installDist --no-daemon

FROM eclipse-temurin:25-jre
WORKDIR /opt/auth-server
COPY --from=build /workspace/auth-server/build/install/auth-server /opt/auth-server
EXPOSE 8080
ENV AUTH_SERVER_PORT=8080
ENTRYPOINT ["/opt/auth-server/bin/auth-server"]
