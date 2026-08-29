FROM eclipse-temurin:21-jdk-alpine
RUN apk add --no-cache socat
WORKDIR /opt
COPY Gate.java /opt/Gate.java
RUN javac Gate.java \
 && jar cfe lic.jar Gate Gate.class 'Gate$1.class' 2>/dev/null || jar cfe lic.jar Gate Gate.class
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
