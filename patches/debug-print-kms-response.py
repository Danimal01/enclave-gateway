#!/usr/bin/env python3
# DEBUG-ONLY (not shipped): make the kmstool print the KMS response body on a
# non-200 answer, so we can see the exact GenerateDataKey 400 reason. Reverts
# cleanly via the .bak the gate-5 build kept. Run on the host:
#   python3 debug-print-kms-response.py ~/aws-nitro-enclaves-sdk-c/source/kms.c
import sys
p = sys.argv[1]
s = open(p).read()
old = 'fprintf(stderr, "Got non-200 answer from KMS: %d\\n", rc);'
new = 'fprintf(stderr, "Got non-200 answer from KMS: %d RESP=%s\\n", rc, response ? (const char *)response->bytes : "(null)");'
n = s.count(old)
if n == 0:
    print("NO_MATCH (already patched or format differs)")
else:
    open(p, "w").write(s.replace(old, new))
    print(f"PATCHED {n} non-200 print(s) to include the KMS response body")
