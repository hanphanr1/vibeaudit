CREATE TABLE public.orders (id bigint, owner_id uuid);
CREATE VIEW public.order_rows WITH (security_invoker = true) AS SELECT id FROM public.orders;
CREATE MATERIALIZED VIEW public.order_cache AS SELECT id FROM public.orders;
REVOKE SELECT ON public.order_cache FROM PUBLIC, anon, authenticated;
CREATE FUNCTION public.my_orders() RETURNS SETOF public.orders
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT * FROM public.orders WHERE owner_id = auth.uid(); $$;
INSERT INTO storage.buckets (id, name, public) VALUES ('receipts', 'receipts', false);
CREATE POLICY "read own objects" ON storage.objects FOR SELECT TO authenticated USING (owner_id = auth.uid()::text);
