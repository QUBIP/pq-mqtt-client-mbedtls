package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @ENGINESDIR @ENGINESDIR_REL_LIBDIR
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $VERSION @LDLIBS
);

our @PREFIX                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl' );
our @libdir                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/lib64' );
our @BINDIR                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/bin' );
our @BINDIR_REL_PREFIX          = ( 'bin' );
our @LIBDIR                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/lib64' );
our @LIBDIR_REL_PREFIX          = ( 'lib64' );
our @INCLUDEDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include' );
our @APPLINKDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/include/openssl' );
our @APPLINKDIR_REL_PREFIX      = ( 'include/openssl' );
our @ENGINESDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/lib64/engines-3' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines-3' );
our @MODULESDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/lib64/ossl-modules' );
our @MODULESDIR_REL_LIBDIR      = ( 'ossl-modules' );
our @PKGCONFIGDIR               = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/lib64/pkgconfig' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( 'pkgconfig' );
our @CMAKECONFIGDIR             = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/installs/openssl/lib64/cmake/OpenSSL' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( 'cmake/OpenSSL' );
our $VERSION                    = '3.3.2';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, '-ldl -pthread ')
    : split(/ +/, '-ldl -pthread ');

1;
