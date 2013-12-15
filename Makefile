OPENLDAP_SRC=./openldap-2.4.16
CPPFLAGS+=-I${OPENLDAP_SRC}/include -I${OPENLDAP_SRC}/servers/slapd -I${OPENLDAP_SRC}/debian/build/include/
LDFLAGS+=-L/usr/local/openldap-2.4.16
CC=gcc

all: autoPosixIds.so

autoPosixIds.so: autoPosixIds.c
	$(CC) -shared $(CPPFLAGS) $(LDFLAGS) -Wall -o $@ $?

clean:
	rm autoPosixIds.so


#########################################################
# the rest of this makefile is used for testing purposes

TEST_ARGS=-x -D "cn=admin,dc=jhosting,dc=mab" -W

install: autoPosixIds.so
	/etc/init.d/slapd stop
	cp autoPosixIds.so /usr/lib/ldap/
	/etc/init.d/slapd start

uninstall:
	rm -fv /usr/lib/ldap/autoPosixIds.so

test:
	ldapadd $(TEST_ARGS) -f ldif/autoPosixIds.ldif
	tail /var/log/debug

testclean:
	ldapdelete $(TEST_ARGS) "uid=autoPosixIds,ou=Users,dc=jhosting,dc=mab"
