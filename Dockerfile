FROM maven:3.6.0-jdk-8-slim AS BUILDER

RUN apt update \
    && apt-get upgrade -y \
    && apt install -y git libcurl3-gnutls libgnutls30 procps \
    && dpkg -l | grep libgnutls \
    && rm -r /var/lib/apt/lists/*

COPY src /src/WS-TLS-Scanner/src
COPY pom.xml /src/WS-TLS-Scanner
COPY maven-eclipse-codestyle.xml /src/WS-TLS-Scanner
COPY license_header_plain.txt /src/WS-TLS-Scanner
WORKDIR /src

RUN git clone --branch 3.2 https://github.com/RUB-NDS/TLS-Attacker.git \
    && git clone --recursive --branch 2.11.1 https://github.com/RUB-NDS/TLS-Scanner.git

RUN cd /src/TLS-Attacker && mvn clean install -DskipTests=true \
    && cd /src/TLS-Scanner && mvn clean install -DskipTests=true 
    

RUN mvn -f /src/WS-TLS-Scanner/pom.xml clean package


FROM tomcat:alpine
COPY --from=BUILDER /src/WS-TLS-Scanner/target/WS-TLS-Scanner-*.war /usr/local/tomcat/webapps/ROOT.war
RUN rm /usr/local/tomcat/webapps/ROOT -r -f
EXPOSE 8080
