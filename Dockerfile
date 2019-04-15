FROM tomcat:latest as BUILDER

WORKDIR /src

RUN apt update \
    && apt-get upgrade -y \
    && apt install -y git maven libcurl3-gnutls default-jdk libgnutls30 procps \
    && dpkg -l | grep libgnutls \
    && rm -r /var/lib/apt/lists/*

RUN git clone --branch 2.8 https://github.com/RUB-NDS/TLS-Attacker.git \
    && git clone --branch 2.6.1 https://github.com/RUB-NDS/TLS-Scanner.git \
    && git clone --branch master https://github.com/SIWECOS/WS-TLS-Scanner.git

RUN cd /src/TLS-Attacker && mvn clean install -DskipTests=true \
    && cd /src/TLS-Scanner && mvn clean install -DskipTests=true \
    && cd /src/WS-TLS-Scanner && mvn clean install -DskipTests=true


FROM tomcat:alpine

COPY --from=BUILDER /src/WS-TLS-Scanner/target/WS-TLS-Scanner-*.war /usr/local/tomcat/webapps/ROOT.war

RUN rm /usr/local/tomcat/webapps/ROOT -r -f

EXPOSE 8080
