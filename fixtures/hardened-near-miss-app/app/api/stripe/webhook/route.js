export async function POST(request) {
  const payload = await request.text();
  const signature = request.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(payload,signature,webhookSecret);
  return store.record(event.type);
}
