# Makes the server certificate for the names localhost and 127.0.0.1, then
# runs slapd in the foreground on ldap:// (StartTLS) and ldaps://.
set -e
mkdir -p /etc/openldap/tls /run/openldap /var/lib/openldap/data
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -keyout /etc/openldap/tls/server.key -out /etc/openldap/tls/server.crt 2>/dev/null
chmod 644 /etc/openldap/tls/server.key
exec slapd -d 0 -f /etc/openldap/slapd.conf -h "ldap:/// ldaps:///"
