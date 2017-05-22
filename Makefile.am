bin_PROGRAMS = choparp
choparp_SOURCES = src/choparp.c
man_MANS = src/choparp.8

AM_TESTS_ENVIRONMENT = \
	AM_BUILDDIR='$(abs_top_builddir)'; \
	AM_SRCDIR='$(abs_top_srcdir)'; \
	AM_SHELL='$(SHELL)'; \
	export AM_BUILDDIR AM_SRCDIR AM_SHELL ;

LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh --comments

TEST_EXTENSIONS = .sh

SH_LOG_DRIVER = $(LOG_DRIVER)
SH_LOG_COMPILER = $(SHELL)

TESTS = test/linux-ns-unshare.sh
EXTRA_DIST = $(TESTS)
