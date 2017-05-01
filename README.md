back-crts
=========

LDAP backend module for CRTS. Allows arbitrary file read/write and command
execution as the user slapd runs as.

Drop the `back-crts` directory in `servers/slapd` in the openldap source and do
some trickery to its build system to build back-crts.

### TODO
* Actually document trickery.
* Clean up CRTS-specific hardcoded stuff
* Generally make less janky
* Expand capabilities
