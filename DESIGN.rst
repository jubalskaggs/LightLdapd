=================
LightLdapd DESIGN
=================

This document is very preliminary.

Coding Style
============

Consistant style is good. There are many C coding styles. We want to
pick a popular one and stick with it. The orignal entente code was
formated pretty closely to the linux kernel style, but with unusually
long lines. We choose the linux style with a max line length of 120.
The GNU indent tool can reformat code to comply with this.

Always use typedef names instead of struct names when possible to
minimize code noise.  Both libev and asn1c have many typedef's using
consistant naming conventions of ev_* or *_t. We can use sed to
automatically enforce this when the struct and typedef names are the
same.

Indent needs a "-T typename" for every single userdefined type,
otherwise it inserts a space between * and the indentifier on pointer
variable and argument definitions. We can automatically correct this
with sed.

We add a "tidy" make target to automatically reformat all the *.c
files. See the Makefile to see what this includes. Always run "make
tidy" before you commit.

Error Handling
==============

malloc failures
---------------

There are three main approaches handling malloc failures, in order of
increasing complexity;

1. Don't even check for it. malloc is never going to fail, since a
system will thrash itself into a swapping coma before letting that
happen. If somehow it ever does fail, the first attempt to dereference
it will segfault and kill your job, which is probably the best thing
you can do on a system that overcommitted. The effort vs return on
checking for malloc failures is not worth it.

2. Check for it, log an error and die. A segfault on dereferencing
will give very little hint on what went wrong, and will look like a
bug. It can also happen very far away from the malloc that failed,
making it difficult to debug what happened. A "malloc-or-die" function
or macro is simple, and many things use xmalloc for this. Note glib
has g_malloc().

3. Check for it, and gracefully recover from failures. Dieing is never
nice. The operation that required the malloc should revert any
progress made and report the failure in a suitable way. This ensures
that the job keeps running and can continue sucessfully handling other
operations, including retries of the failed operation.  This can be
tricky to get right, and it is easy to miss cleaning everything up and
forget to free something. This turns your malloc failure handling into
a memory leak, which will not help.

There is not much point in using a mixture of options, except in the
case where particular operations are known to have large "risky"
mallocs compared to the rest of the program. In that case it might
make sense to use option 3 for those operations, and options 1 or 2
for the rest.

It also depends on the libraries used. There is no point in
trying to do option 3 if the libraries you are using use option 1 or
2; the library is going to kill you anyway. If your library does use
option 3, then you need to be vigilant about checking its error codes
for malloc failures and responding appropriately.

The original entente code attempted to use option 3, but missed a few
cases. Once the bind/listen is done, on malloc failures it attempts to
only close the individual connection, not kill the whole process.
Fortunately the individual connections and requests are pretty simple,
so are easy to clean up.

The asn1c library does seem to use option 3, and reports errors for
malloc failures. libev's docs suggest that it will behave badly on
malloc failures, dieing or behaving in and undefined way.

For LightLdap, we want to be capable of running on low-end router
hardware, which can have limited ram/swap. This means the assumptions
in option 1. about the chance of malloc failues might not hold. Option
3. is feasible to implement, but it is questionable if it's worth it.
malloc failures killing connections means we would be running pretty
degraded, and it might be better to just die. If it is our process
that has a memory leak, dieing could help the whole system recover.
However, there are other failure conditions that we absolutely don't
want to die for, like encoding/decoding errors, so we already need
graceful error handling.

So, we will wherever possible handle errors by cleaning up and closing
the connection. If cleaning everything up is very hard, it is better
to die than to leak.


----

http://github.com/dbaarda/LightLdapd
$Id: DESIGN,v 65b64de6b1e1 2014/01/20 02:32:20 abo $
