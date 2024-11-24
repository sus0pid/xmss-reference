#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h> // For gettimeofday()

#include "../wots.h"
#include "../randombytes.h"
#include "../params.h"

// Function to calculate elapsed time in microseconds
long long time_in_microseconds(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec) * 1000000LL + (end.tv_usec - start.tv_usec);
}

int main() {
    xmss_params params;
    // TODO: Test with more OIDs
    uint32_t oid = 0x00000001; /* XMSS_SHA2-20_256 */

    /* Parse OID to get parameters for WOTS */
    xmss_parse_oid(&params, oid);

    // Buffers
    unsigned char seed[params.n];
    unsigned char pub_seed[params.n];
    unsigned char pk1[params.wots_sig_bytes];
    unsigned char pk2[params.wots_sig_bytes];
    unsigned char sig[params.wots_sig_bytes];
    unsigned char m[params.n];
    uint32_t addr[8] = {0};

    // Generate random input data
    randombytes(seed, params.n);
    randombytes(pub_seed, params.n);
    randombytes(m, params.n);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing WOTS signature and PK derivation...\n");

    struct timeval start, end;
    long long keygen_time, sign_time, verify_time;

    // Measure key generation time
    gettimeofday(&start, NULL);
    wots_pkgen(&params, pk1, seed, pub_seed, addr);
    gettimeofday(&end, NULL);
    keygen_time = time_in_microseconds(start, end);

    // Measure signing time
    gettimeofday(&start, NULL);
    wots_sign(&params, sig, m, seed, pub_seed, addr);
    gettimeofday(&end, NULL);
    sign_time = time_in_microseconds(start, end);

    // Measure verification time
    gettimeofday(&start, NULL);
    wots_pk_from_sig(&params, pk2, sig, m, pub_seed, addr);
    gettimeofday(&end, NULL);
    verify_time = time_in_microseconds(start, end);

    // Check if the derived public key matches the original
    if (memcmp(pk1, pk2, params.wots_sig_bytes)) {
        printf("failed!\n");
        return -1;
    }

    printf("successful.\n");
    printf("Key Generation Time: %lld microseconds\n", keygen_time);
    printf("Signing Time: %lld microseconds\n", sign_time);
    printf("Verification Time: %lld microseconds\n", verify_time);

    return 0;
}

