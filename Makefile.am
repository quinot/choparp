bin_PROGRAMS = choparp
choparp_SOURCES = src/choparp.c
man_MANS = src/choparp.8

AM_TESTS_ENVIRONMENT = \
	choparp_abspath='$(abs_top_builddir)'/choparp; \
	export choparp_abspath;

LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

TEST_EXTENSIONS = .sh

SH_LOG_DRIVER = $(LOG_DRIVER)
SH_LOG_COMPILER = $(SHELL)

TESTS = test/linux-veth.sh
EXTRA_DIST = $(TESTS)
