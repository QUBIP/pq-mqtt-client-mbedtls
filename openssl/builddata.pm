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

our @PREFIX                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl' );
our @libdir                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl' );
our @BINDIR                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl/apps' );
our @BINDIR_REL_PREFIX          = ( 'apps' );
our @LIBDIR                     = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl' );
our @LIBDIR_REL_PREFIX          = ( '' );
our @INCLUDEDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl/include', '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl/include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include', './include' );
our @APPLINKDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl/ms' );
our @APPLINKDIR_REL_PREFIX      = ( 'ms' );
our @ENGINESDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl/engines' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines' );
our @MODULESDIR                 = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl/providers' );
our @MODULESDIR_REL_LIBDIR      = ( 'providers' );
our @PKGCONFIGDIR               = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '.' );
our @CMAKECONFIGDIR             = ( '/home/secpat/Desktop/QUBIP/qubip_csic_mbedtls/openssl' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '.' );
our $VERSION                    = '3.3.2';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, '-ldl -pthread ')
    : split(/ +/, '-ldl -pthread ');

1;
