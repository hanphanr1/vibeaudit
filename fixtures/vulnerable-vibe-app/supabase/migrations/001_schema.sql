CREATE TABLE public.orders (id bigint, user_id uuid);
CREATE POLICY "any insert" ON public.orders FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "any update" ON public.orders FOR UPDATE TO authenticated USING (true);
CREATE POLICY "any delete" ON public.orders FOR DELETE TO public USING (true);
CREATE POLICY "any operation" ON public.orders FOR ALL TO authenticated USING (true);
CREATE VIEW public.order_rows AS SELECT id FROM public.orders;
CREATE MATERIALIZED VIEW public.order_cache AS SELECT id FROM public.orders;
CREATE FUNCTION public.orders_for(user_id uuid) RETURNS SETOF public.orders
LANGUAGE sql SECURITY DEFINER AS $$ SELECT * FROM public.orders WHERE orders.user_id = orders_for.user_id; $$;
INSERT INTO storage.buckets (id, name, public) VALUES ('receipts', 'receipts', true);
CREATE POLICY "bucket members" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'receipts');
