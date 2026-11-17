FROM docker.io/homeassistant/home-assistant:2025.6.3
# ldapsearch for /config/ldap_auth.sh
RUN apk add --no-cache openldap-clients
