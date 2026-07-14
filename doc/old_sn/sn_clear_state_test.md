## SN clear state test

This document describes how to reset SN state for a fixed activation code and verify the behavior.

Activation code (fixed): `zX6cV7bN8mK9lJ0hG1fD`
Note: `clear_state_by_active_code` does not accept any parameters.

### RPC endpoint

- Clear state URL: `https://sn.buckyos.ai/kapi/sn/bns`
- Auth check URL: `https://sn.buckyos.ai/kapi/sn/auth`
- Method: `POST`
- Content-Type: `application/json`

### Clear state (curl)

```bash
curl -sS -X POST "https://sn.buckyos.ai/kapi/sn/bns" \
  -H "Content-Type: application/json" \
  -d '{"id":1,"method":"clear_state_by_active_code","params":{}}'
```

Expected response fields:

- `code: 0`
- `deleted_users`, `deleted_devices`, `deleted_domain_records`, `deleted_did_documents`
- `activation_code_reset: true`

### Verify activation code is reusable

```bash
curl -sS -X POST "https://sn.buckyos.ai/kapi/sn/auth" \
  -H "Content-Type: application/json" \
  -d '{"id":2,"method":"check_active_code","params":{"active_code":"zX6cV7bN8mK9lJ0hG1fD"}}'
```

Expected response fields:

- `valid: true`

### Verify username is released

```bash
curl -sS -X POST "https://sn.buckyos.ai/kapi/sn/auth" \
  -H "Content-Type: application/json" \
  -d '{"id":3,"method":"check_username","params":{"username":"test"}}'
```

Expected response fields:

- `valid: true`
