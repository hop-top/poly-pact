# OpenLDAP 2.6 server of the LDAP adapter's integration tier: the memberof and
# ppolicy overlays, a self-signed certificate made at start, and the access
# control the seed of spec/v1.0/fixtures/adapters/ldap expects.
FROM alpine:3.22
RUN apk add --no-cache openldap openldap-back-mdb openldap-overlay-memberof openldap-overlay-ppolicy openldap-clients openssl
COPY slapd.conf /etc/openldap/slapd.conf
COPY start.sh /start.sh
EXPOSE 389 636
CMD ["/bin/sh", "/start.sh"]
