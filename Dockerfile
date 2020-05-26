FROM jboss/keycloak:10.0.1

ADD ./protocol-mappers/target/keycloak-regex-mappers.jar /opt/jboss/keycloak/standalone/deployments/
