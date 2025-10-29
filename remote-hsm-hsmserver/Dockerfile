FROM openjdk:21-jdk-buster

EXPOSE 8080
EXPOSE 8009
EXPOSE 8008

COPY target/remote-hsm-hsmserver-*.jar /app.jar

# Copy demo data
COPY target/test-classes /target/test-classes

ENTRYPOINT ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000","-jar","/app.jar"]
