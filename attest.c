/* gateway/attest.c: the GATEWAY's boot-time attestation emitter (spec 6.5,
 * Claim A). Baked into the measured EIF, so its bytes are part of PCR0_G and a
 * stranger rebuilding the published mirror reproduces the same measurement.
 *
 * It asks the Nitro Security Module for a signed attestation document (which
 * carries PCR0 = the SHA-384 of this exact image) and prints it base64 on
 * stdout, prefixed "ATTDOC:". The entrypoint pipes that to the parent over vsock
 * (:8002); the parent publishes it as the public static artifact the open proof
 * page verifies in the visitor's browser. No secrets, no key material, no
 * network — just "this published image is the one genuinely running."
 *
 * user_data is a FIXED label (not a per-build value) so the build stays
 * byte-reproducible; the binding that matters (PCR0_G <-> published source) is
 * carried by PCR0 itself and pinned in the web app's gateway-release.json. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libnsm exports (Nitro Security Module); resolvable only inside an enclave. */
extern int nsm_lib_init(void);
extern void nsm_lib_exit(int fd);
extern int nsm_get_attestation_doc(int fd,
    unsigned char *user_data, unsigned int user_data_len,
    unsigned char *nonce, unsigned int nonce_len,
    unsigned char *public_key, unsigned int public_key_len,
    unsigned char *att_doc, unsigned int *att_doc_len);

static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64(const unsigned char *in, unsigned int n) {
    unsigned int i;
    for (i = 0; i + 2 < n; i += 3) {
        putchar(T[in[i] >> 2]);
        putchar(T[((in[i] & 3) << 4) | (in[i+1] >> 4)]);
        putchar(T[((in[i+1] & 15) << 2) | (in[i+2] >> 6)]);
        putchar(T[in[i+2] & 63]);
    }
    if (i < n) {
        putchar(T[in[i] >> 2]);
        if (i + 1 < n) {
            putchar(T[((in[i] & 3) << 4) | (in[i+1] >> 4)]);
            putchar(T[(in[i+1] & 15) << 2]);
        } else {
            putchar(T[(in[i] & 3) << 4]);
            putchar('=');
        }
        putchar('=');
    }
    putchar('\n');
}

int main(void) {
    int fd = nsm_lib_init();
    if (fd < 0) { fprintf(stderr, "ATTEST_FAIL nsm_lib_init=%d\n", fd); return 1; }
    unsigned char doc[16384];
    unsigned int doclen = sizeof(doc);
    unsigned char ud[] = "sessions-gateway-claim-a";
    int rc = nsm_get_attestation_doc(fd, ud, (unsigned int)(sizeof(ud) - 1), NULL, 0, NULL, 0, doc, &doclen);
    if (rc != 0) { fprintf(stderr, "ATTEST_FAIL rc=%d\n", rc); nsm_lib_exit(fd); return 2; }
    fprintf(stderr, "ATTEST_OK len=%u\n", doclen);
    printf("ATTDOC:");
    b64(doc, doclen);
    nsm_lib_exit(fd);
    return 0;
}
