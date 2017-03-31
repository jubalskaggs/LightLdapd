===============
LightLdapd TODO
===============

This is a list of outstanding TODO items in aproximate order of most
important first. Feel free to add things to this list. Please ensure
that user visible things are moved from here to the NEWS file when
they get done.

Items
=====

* Improve project documentation:

  Add documentation based on templates in
  http://minkirri.apana.org.au/~abo/projects/prjdocs/.

* Change license from MIT to GPL?

  Would prefer to require contributions to come back rather than spawn private
  forks. Need to contact entente author to check this is OK.
  
* Change name from entente to lightldapd.

  Forked project is now LightLdpad, need to make binary and cfgs match.

* Tidy code.

  Reformat again using a different common style? I'm not keen on tabs.

* Improve design.

  Restructure using ldap_server, ldap_connection, ldap_request
  structs, copying the design of https://github.com/taf2/libebb.

* Add logging.

  Using syslog. Or using glib's logging?

* Extend Search support.

  Extend search support enough to support libnss-ldap clients,
  exporting the local nsswitch view of passwd/group/etc.

* Add StartTLS support.

  Probably using gnutls.

----

$Id: TODO,v 1.40 2004/10/18 02:30:53 abo Exp $
