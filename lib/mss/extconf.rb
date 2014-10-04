require 'mkmf'
$CFLAGS += " -DMSS_CALC_RETAIN -I include"
create_makefile("mss_wrapper", 'src')
