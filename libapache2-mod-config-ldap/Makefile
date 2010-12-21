APXS := $(shell if ! which apxs; then which apxs2; fi)
VERSION=`cat VERSION`

all: mod_config_ldap.o

mod_config_ldap.o: mod_config_ldap.c
	$(APXS) -Wc,-Wall -Wc,-Werror -Wc,-g -DDEBUG \
        -Wc,-DMOD_CONFIG_LDAP_VERSION=\\\"mod_config_ldap/$(VERSION)\\\" \
        -Wc,-DLDAP_DEPRECATED=0 \
        -lldap -c mod_config_ldap.c

clean:
	rm -rf *.o *.so *.lo *.la *.slo *~ .libs

install:
	$(APXS) -i mod_config_ldap.la

.PHONY: all clean install
