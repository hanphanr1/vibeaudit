export async function POST(request) {
  await supabase.auth.getSession();
  return orders.create(await request.json());
}
