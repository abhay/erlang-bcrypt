## Copyright (c) 2008 Hunter Morris <huntermorris@gmail.com>

## Permission to use, copy, modify, and distribute this software for any
## purpose with or without fee is hereby granted, provided that the above
## copyright notice and this permission notice appear in all copies.

## THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
## WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
## MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
## ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
## WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
## ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
## OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

SUBDIRS = lib

localdoc_DATA = README.gz LICENSE.gz

DISTCLEANFILES = $(localdoc_DATA)

EXTRA_DIST = README LICENSE

README.gz: $(top_srcdir)/README
	-gzip -9 < $< > $@

LICENSE.gz: $(top_srcdir)/LICENSE
	-gzip -9 < $< > $@

.PHONY: local-clean
local-clean: maintainer-clean
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may need special tools to rebuild."
	rm -f $(top_srcdir)/INSTALL
	rm -f $(top_srcdir)/acinclude.m4
	rm -f $(top_srcdir)/aclocal.m4
	rm -f $(top_srcdir)/config.h.in
	rm -f $(top_srcdir)/configure
	rm -f $(top_srcdir)/*.tar.gz
	rm -f $(top_srcdir)/*.tar.gz.*
	rm -fr $(top_srcdir)/build-aux
	rm -fr $(top_srcdir)/m4
	find $(top_srcdir) -name Makefile.in -exec rm {} \;

.PHONY: distsign
distsign: distcheck
	gpg --armor --detach-sig \
	    < $(top_srcdir)/$(distdir).tar.gz \
	    > $(top_srcdir)/$(distdir).tar.gz.asc
	md5sum $(top_srcdir)/$(distdir).tar.gz \
	    > $(top_srcdir)/$(distdir).tar.gz.md5
	sha1sum $(top_srcdir)/$(distdir).tar.gz \
	    > $(top_srcdir)/$(distdir).tar.gz.sha
