FROM eclipse-temurin:8-jdk AS build

WORKDIR /app

# JAR vulnerabili (2.14.1)
RUN curl -fsSL -o log4j-api-2.14.1.jar  https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar \
 && curl -fsSL -o log4j-core-2.14.1.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar

COPY VulnApp.java /app/
COPY log4j2.xml /app/

RUN javac -cp "log4j-api-2.14.1.jar:log4j-core-2.14.1.jar:." VulnApp.java
# ==================================================================
FROM eclipse-temurin:8-jre
WORKDIR /app

COPY --from=build /app /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping net-tools curl traceroute tcpdump iptables \
 && rm -rf /var/lib/apt/lists/*

EXPOSE 8080

# Abilita il class loading remoto (per PoC)
ENV JAVA_TOOL_OPTIONS="-Dcom.sun.jndi.ldap.object.trustURLCodebase=true"

CMD ["java","-Dcom.sun.jndi.ldap.object.trustURLCodebase=true","-cp", ".:log4j-api-2.14.1.jar:log4j-core-2.14.1.jar","VulnApp"]

