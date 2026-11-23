# Secrets and webhooks

From the trusted scanner checkout: `npm run cli -- scan /path/to/project --json --fail-on none`. MCP: call `vibeaudit_scan_path` with `{"path":"/path/to/project"}` and `vibeaudit_list_rules` with `{}`. Keep the target and exclusions unchanged on rescan.

1. For an apparent credential, verify the provider and its scope from masked evidence. A Supabase public anon or publishable key is not a service-role credential; public claims still require RLS. A confirmed service-role key belongs only in trusted server configuration. A tracked dotenv file is finding evidence without reading its contents.
2. Remove hardcoded or public-prefixed secrets, then coordinate rotation through the approved credential store. Do not copy values into reports or assume removing them from the latest file erases history. Confirm the client bundle receives only explicitly public keys.
3. For Stripe webhooks, check that the handler reads the exact body bytes or text, verifies the signature with the configured endpoint secret, and rejects failures before side effects. Verify event type and idempotency. An API route named webhook is not evidence of Stripe use.
4. Test with disposable local values and signed fixture events. Assert failed verification writes nothing and duplicate delivery cannot record the event twice. Rescan and remove any unredacted local scratch material.
