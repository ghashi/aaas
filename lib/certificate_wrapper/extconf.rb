require 'mkmf'
require 'pp'

pp $configure_args

LIBDIR      = RbConfig::CONFIG['libdir']
INCLUDEDIR  = RbConfig::CONFIG['includedir']

HEADER_DIRS = [INCLUDEDIR,
               Dir.pwd + "/certificate/hashbasedsignature-code/workspace/include",
               Dir.pwd + "/certificate/micro-ecc",
               Dir.pwd + "/certificate"]

LIB_DIRS = [LIBDIR, Dir.pwd + "/certificate/bin"]

dir_config('certificate_wrapper', HEADER_DIRS, LIB_DIRS)

unless find_header('certificate.h')
  abort "certificate.h is missing"
end

unless find_header('cert_time.h')
  abort "cert_time.h is missing"
end

unless find_header('ntru.h')
  abort "ntru.h is missing"
end

unless have_library('crypto', 'mss_verify')
  abort "libcrypto is missing"
end

unless have_library('certificate', 'generate_certificate')
  abort "libcertificate is missing"
end
create_makefile("certificate_wrapper")
