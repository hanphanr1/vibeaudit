# Supabase RLS

From the trusted scanner checkout: `npm run cli -- scan /path/to/project --json --fail-on none`. MCP: call `vibeaudit_scan_path` with `{"path":"/path/to/project"}` and `vibeaudit_list_rules` with `{}`. Keep the target and exclusions unchanged on rescan.

1. Read applicable migrations in replay order. If the table was dropped or a later migration enables RLS, document the final state rather than marking the initial statement vulnerable. If an enable is followed by disable, confirm the finding. Verify live state separately only through the maintainer’s approved process.
2. For an exposed role, check grants, then each operation and effective USING/WITH CHECK condition. A policy for one operation does not grant another. Treat unrestricted writes or updates with unscoped checks as confirmed when reachable. Compare IDs against verified session identity, not a request parameter.
3. For views, check security_invoker and base policies. For materialized views, validate reader grants; invoker mode is not a materialized-view fix. For SECURITY DEFINER functions, qualify names and use an empty or trusted search path. Inspect storage bucket visibility and object ownership separately.
4. Add a forward migration using the exact qualified table and policy. Test locally that the owner is allowed, a second user is denied, and anonymous access matches the intended design. Run the same scan again, then gate with `npm run cli -- scan /path/to/project --fail-on high`.
