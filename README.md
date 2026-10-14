# Lasso Guardrail for WSO2 AI Gateway

A custom [WSO2 API Platform AI Gateway](https://wso2.com/api-platform/) policy that screens LLM chat traffic with [Lasso Security](https://www.lasso.security/)'s `classify` / `classifix` API.

- **Request phase:** screens the prompt (`messages`) before it reaches the model.
- **Response phase:** screens the completion (`choices[].message`) before it reaches the client.
- **Blocking:** blocks on any `BLOCK`-severity finding, such as jailbreak, prompt injection, harmful content, PII, code-security issues or custom policy violations.
- **Masking (optional):** uses `/classifix` and rewrites `AUTO_MASKING` findings in place. A `BLOCK` finding still blocks when masking is on.
- **Fail-open or fail-closed:** set `passthroughOnError` per phase. An invalid API key always blocks.
- **Session correlation:** a client-supplied session header ties multiple turns into one dialogue in Lasso.

Ported from Lasso's [Kong AI guardrail plugin](https://github.com/lasso-security/kong-ai-lasso-guardrail).

This repo also includes a **mock Lasso server**, so you can demo the policy end to end without a Lasso account.

## Repository layout

| Path | What it is |
|---|---|
| `lasso-guardrail/` | The Go policy: `lassoguardrail.go`, its tests, and `policy-definition.yaml` |
| `mock-lasso-server/server.py` | Mock of Lasso's `classify`/`classifix` API. PII only (email, phone, SSN, credit card). Python standard library only |
| `examples/` | A sample route, a docker-compose service for the mock, and the `config.toml` snippet |

## Policy parameters

| Parameter | Default | Description |
|---|---|---|
| `request.passthroughOnError` | `true` | Fail-open when the Lasso call fails during the request phase |
| `request.includeTools` | `true` | Forward the request's `tools` definitions to Lasso |
| `response.passthroughOnError` | `true` | Fail-open when the Lasso call fails during the response phase |
| `masking` | `false` | Use `/classifix` and mask `AUTO_MASKING` findings in place |
| `sessionHeader` | `x-session-id` | Header carrying the conversation ID |
| `userHeader` | `x-lasso-user-id` | Header carrying the end-user ID |
| `sourceType` | `wso2-ai-gateway` | Reported to Lasso as `source.type` |
| `timeoutMillis` | `10000` | Timeout for the Lasso API call |

System parameters, set in `configs/config.toml`:

| Parameter | Description |
|---|---|
| `lassoApiKey` | Lasso API key, sent as the `lasso-api-key` header. Required |
| `lassoApiBase` | Lasso API base URL. Default: `https://server.lasso.security/gateway/v3` |

## Usage

1. Copy `lasso-guardrail/` into your gateway distribution under `policies/`.

2. Register it in `build.yaml`:

   ```yaml
   policies:
     - name: lasso-guardrail
       filePath: policies/lasso-guardrail
   ```

3. Add the [`config.toml` snippet](examples/config.toml.snippet) and set the environment variables in `api-platform.env`:

   ```bash
   APIP_GW_LASSO_API_KEY=<your-lasso-api-key>
   APIP_GW_LASSO_API_BASE=https://server.lasso.security/gateway/v3
   ```

4. Build the gateway image and bring it up:

   ```bash
   ap gateway image build --name <your-image-name>
   docker compose up -d gateway-controller gateway-runtime
   ```

5. Attach the policy to a route. See [`examples/lasso-mock-route.yaml`](examples/lasso-mock-route.yaml):

   ```yaml
   policies:
     - name: lasso-guardrail
       version: v0
       params:
         request:
           passthroughOnError: true
         response:
           passthroughOnError: true
         masking: true
   ```

## Demo with the mock Lasso server

1. Copy `mock-lasso-server/` into the gateway directory.
2. Add the [`lasso-mock` service](examples/docker-compose.lasso-mock.yaml) to `docker-compose.yaml`.
3. Point the policy at the mock:

   ```bash
   APIP_GW_LASSO_API_BASE=http://lasso-mock:8090/gateway/v3
   APIP_GW_LASSO_API_KEY=mock-lasso-key
   ```

4. Start everything with `docker compose up -d gateway-controller gateway-runtime lasso-mock`, then send a prompt that contains PII:

   ```bash
   curl -s -X POST http://localhost:<port>/openai-lasso-mock/chat/completions \
     -H "Content-Type: application/json" \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is jane.doe@example.com and my SSN is 123-45-6789."}]}'
   ```

   `docker compose logs -f lasso-mock` shows the prompt before and after masking, with `[EMAIL_REDACTED]` and `[SSN_REDACTED]` in place of the real values. The model only ever sees the redacted text.

5. To check that the guardrail actually sits in the request path, run `docker compose stop lasso-mock` and resend the request. The gateway logs `LassoGuardrail: Lasso unavailable — fail-open, allowing`.

   Don't judge this from the model's reply. With the mock stopped, the unmasked PII reaches the model, which may still refuse to repeat it. Use the gateway log line as evidence instead.

## Running the tests

```bash
cd lasso-guardrail
go test ./...
```

## Disclaimer

This is a proof of concept. It is not an official WSO2 or Lasso Security product.
