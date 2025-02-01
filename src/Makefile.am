bin_PROGRAMS = mailfilter
#mailfilter_SOURCES = mailfilter.c js_sys.c smtp_server.c js_smtp.c js_dns.c string_tools.c mod_extscan.c mod_clamav.c mod_dkim.c base64.c pexec.c bfd.c
mailfilter_SOURCES = mailfilter.c js_sys.c smtp_server.c js_smtp.c js_dns.c string_tools.c mod_extscan.c bfd.c

if HAVE_SPF2
    mailfilter_SOURCES += mod_spf.c
endif
