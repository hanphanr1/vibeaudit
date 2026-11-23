import { createClient } from '@/lib/supabase/server';

export async function POST(request) {
  const supabase = await createClient();
  const {data:{user}} = await supabase.auth.getUser();
  if (!user) return Response.json({ error:'Sign in' }, {status:401});
  return orders.create({ owner_id:user.id, data:await request.json() });
}
