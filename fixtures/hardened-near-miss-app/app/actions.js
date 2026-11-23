'use server';
import { createClient } from '@/lib/supabase/server';

export async function saveOrder(order) {
  const supabase = await createClient();
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) throw new Error('Sign in');
  return db.orders.create({ ...order, owner_id:user.id });
}
