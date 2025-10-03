from tomcat

RUN apt update && apt install -y iproute2 net-tools iputils-ping lsb-release

ENV CATALINA_OPTS="-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
