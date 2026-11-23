ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY "write own orders" ON public.orders FOR UPDATE TO authenticated USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());
