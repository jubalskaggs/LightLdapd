======================
LightLdapd DEVELOPMENT
======================

This document is very preliminary.

See the DESIGN document for more detailed explanations behind some of
these procedures.

Testing
=======

When running entente for tesing use;

sudo ./entente -l -a

When searching with ldapsearch, you should use;

ldapsearch "user=abo" -b "dc=entente" -h localhost -v -x -D "cn=abo,dc=entente" -W

-b is base DN
-h is the host
-v is verbose output
-x is simple bind
-D is bind DN
-W is prompt for passwd

Without -b it uses the default from /etc/ldap/ldap.conf
Without -D and -W it does an anonymous bind.
With -D "" it also does an anonymous bind.

Coding Style
============

The coding style used is the linux style with a max line length of
120.

Always use typedef names instead of struct names when possible. Type
names should end in *_t?

Always run "make tidy" to automatically reformat your code before
committing.


Error Handling
==============

Wherever possible handle errors by cleaning up and closing the
connection, leaving the server running. If cleaning everything up is
very hard, it is better to exit the whole server than to leak.

For memory alloc failures, we immediately exit. Use the provided
XNEW, XNEW0, XSTRDUP, etc macros to do this.

----

http://github.com/dbaarda/LightLdapd
$Id: DEVELOPMENT,v 65b64de6b1e1 2014/01/20 02:32:20 abo $
