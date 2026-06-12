#!/usr/bin/env python3
# Gate 5 (docs/gateway-rebuild-runbook.md): add --encryption-context to
# kmstool_enclave_cli. The SDK (v0.4.5) library already supports encryption
# context for decrypt (aws_kms_decrypt_blocking_with_context) and via the
# generate_data_key request struct; this patch:
#   1. adds aws_kms_generate_data_key_blocking_with_context to source/kms.c
#      (mirrors the decrypt _with_context: parse JSON context -> hash table),
#   2. declares it in the header,
#   3. wires a --encryption-context CLI flag (JSON arg) into decrypt + genkey.
# The context arg is JSON, e.g. {"SessionsContextId":"<uuid>"}, matching how
# the kms-envelope-v3.mjs transport passes SessionsContextId=<uuid> (the
# transport is updated to emit JSON; see note at the bottom).
#
# Idempotent: each edit asserts it matches exactly once, and re-running detects
# the marker and skips. Run on the host:  python3 apply-kmstool-context-patch.py <SDK_DIR>
import sys, os

SDK = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/aws-nitro-enclaves-sdk-c")
MAIN = os.path.join(SDK, "bin/kmstool-enclave-cli/main.c")
KMS_C = os.path.join(SDK, "source/kms.c")
KMS_H = os.path.join(SDK, "include/aws/nitro_enclaves/kms.h")
MARKER = "aws_kms_generate_data_key_blocking_with_context"

def edit(path, old, new, label):
    with open(path) as f:
        s = f.read()
    if new.strip() and new in s and old not in s:
        print(f"  [skip] {label} (already applied)")
        return
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"  [FAIL] {label}: anchor matched {n} times (expected 1) in {path}")
    s = s.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(s)
    print(f"  [ok]   {label}")

GENKEY_WITH_CONTEXT = '''int aws_kms_generate_data_key_blocking_with_context(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    enum aws_key_spec key_spec,
    const struct aws_string *encryption_context,
    struct aws_byte_buf *plaintext,
    struct aws_byte_buf *ciphertext_blob) {
    AWS_PRECONDITION(client != NULL);
    AWS_PRECONDITION(key_id != NULL);
    AWS_PRECONDITION(plaintext != NULL);
    AWS_PRECONDITION(ciphertext_blob != NULL);

    struct aws_string *response = NULL;
    struct aws_string *request = NULL;
    struct aws_kms_generate_data_key_response *response_structure = NULL;
    struct aws_kms_generate_data_key_request *request_structure = NULL;
    int rc = 0;

    request_structure = aws_kms_generate_data_key_request_new(client->allocator);
    if (request_structure == NULL) {
        return AWS_OP_ERR;
    }

    request_structure->key_id = aws_string_clone_or_reuse(client->allocator, key_id);
    request_structure->key_spec = key_spec;

    request_structure->recipient = aws_recipient_new(client->allocator);
    if (request_structure->recipient == NULL) {
        goto err_clean;
    }
    rc = aws_attestation_request(
        client->allocator, client->keypair, &request_structure->recipient->attestation_document);
    if (rc != AWS_OP_SUCCESS) {
        goto err_clean;
    }
    request_structure->recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;

    if (encryption_context != NULL) {
        struct json_object *context_json = s_json_object_from_string(encryption_context);
        rc = s_aws_hash_table_from_json(client->allocator, context_json, &request_structure->encryption_context);
        json_object_put(context_json);
        if (rc != AWS_OP_SUCCESS) {
            goto err_clean;
        }
    }

    request = aws_kms_generate_data_key_request_to_json(request_structure);
    if (request == NULL) {
        goto err_clean;
    }

    rc = s_aws_nitro_enclaves_kms_client_call_blocking(client, kms_target_generate_data_key, request, &response);
    if (rc != 200) {
        fprintf(stderr, "Got non-200 answer from KMS: %d\\n", rc);
        goto err_clean;
    }

    response_structure = aws_kms_generate_data_key_response_from_json(client->allocator, response);
    if (response_structure == NULL) {
        fprintf(stderr, "Could not read response from KMS: %d\\n", rc);
        goto err_clean;
    }

    rc = s_decrypt_ciphertext_for_recipient(
        client->allocator, &response_structure->ciphertext_for_recipient, client->keypair, plaintext);

    aws_byte_buf_init_copy(ciphertext_blob, client->allocator, &response_structure->ciphertext_blob);
    aws_kms_generate_data_key_request_destroy(request_structure);
    aws_kms_generate_data_key_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);

    return rc;
err_clean:
    aws_kms_generate_data_key_request_destroy(request_structure);
    aws_kms_generate_data_key_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);
    return AWS_OP_ERR;
}

'''

print("kms.c: add genkey _with_context")
edit(KMS_C,
     "int aws_kms_generate_data_key_blocking(\n    struct aws_nitro_enclaves_kms_client *client,\n    const struct aws_string *key_id,\n    enum aws_key_spec key_spec,",
     GENKEY_WITH_CONTEXT + "int aws_kms_generate_data_key_blocking(\n    struct aws_nitro_enclaves_kms_client *client,\n    const struct aws_string *key_id,\n    enum aws_key_spec key_spec,",
     "kms.c genkey _with_context function")

print("kms.h: declare genkey _with_context")
edit(KMS_H,
     "AWS_NITRO_ENCLAVES_API\nint aws_kms_generate_data_key_blocking(",
     "AWS_NITRO_ENCLAVES_API\nint aws_kms_generate_data_key_blocking_with_context(\n"
     "    struct aws_nitro_enclaves_kms_client *client,\n"
     "    const struct aws_string *key_id,\n"
     "    enum aws_key_spec key_spec,\n"
     "    const struct aws_string *encryption_context,\n"
     "    struct aws_byte_buf *plaintext,\n"
     "    struct aws_byte_buf *ciphertext_blob);\n\n"
     "AWS_NITRO_ENCLAVES_API\nint aws_kms_generate_data_key_blocking(",
     "kms.h declaration")

print("main.c: struct field")
edit(MAIN,
     "    const struct aws_string *key_id;\n    enum aws_key_spec key_spec;",
     "    const struct aws_string *key_id;\n    enum aws_key_spec key_spec;\n\n    /* Encryption context as JSON, e.g. {\"SessionsContextId\":\"...\"} */\n    const struct aws_string *encryption_context;",
     "main.c struct app_ctx field")

print("main.c: init field")
edit(MAIN,
     "    ctx->encryption_algorithm = NULL;",
     "    ctx->encryption_algorithm = NULL;\n    ctx->encryption_context = NULL;",
     "main.c init")

print("main.c: long option")
edit(MAIN,
     '    {"length", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, \'l\'},',
     '    {"encryption-context", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, \'C\'},\n    {"length", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, \'l\'},',
     "main.c long_options")

print("main.c: getopt string")
edit(MAIN, '"r:x:k:s:t:c:K:p:a:l:h"', '"r:x:k:s:t:c:K:p:a:l:C:h"', "main.c getopt string")

print("main.c: switch case 'C'")
edit(MAIN,
     "            case 't':\n                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);\n                break;",
     "            case 't':\n                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);\n                break;\n            case 'C':\n                ctx->encryption_context = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);\n                break;",
     "main.c switch case C")

print("main.c: decrypt call")
edit(MAIN,
     "    rc = aws_kms_decrypt_blocking(\n        client, app_ctx->key_id, app_ctx->encryption_algorithm, &ciphertext, &ciphertext_decrypted);",
     "    if (app_ctx->encryption_context != NULL) {\n"
     "        rc = aws_kms_decrypt_blocking_with_context(\n"
     "            client, app_ctx->key_id, app_ctx->encryption_algorithm, &ciphertext,\n"
     "            app_ctx->encryption_context, &ciphertext_decrypted);\n"
     "    } else {\n"
     "        rc = aws_kms_decrypt_blocking(\n"
     "            client, app_ctx->key_id, app_ctx->encryption_algorithm, &ciphertext, &ciphertext_decrypted);\n"
     "    }",
     "main.c decrypt call")

print("main.c: genkey call")
edit(MAIN,
     "    rc = aws_kms_generate_data_key_blocking(client, app_ctx->key_id, app_ctx->key_spec, &plaintext, &ciphertext);",
     "    if (app_ctx->encryption_context != NULL) {\n"
     "        rc = aws_kms_generate_data_key_blocking_with_context(\n"
     "            client, app_ctx->key_id, app_ctx->key_spec, app_ctx->encryption_context, &plaintext, &ciphertext);\n"
     "    } else {\n"
     "        rc = aws_kms_generate_data_key_blocking(client, app_ctx->key_id, app_ctx->key_spec, &plaintext, &ciphertext);\n"
     "    }",
     "main.c genkey call")

print("PATCH APPLIED OK")
