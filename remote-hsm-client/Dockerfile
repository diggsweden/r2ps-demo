FROM eclipse-temurin:21-jdk-jammy
ARG PROFILE=deploy

EXPOSE 8080
EXPOSE 8009
EXPOSE 8008

COPY target/remote-hsm-client-*.jar /app.jar

ENTRYPOINT ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000","-jar","/app.jar"]
