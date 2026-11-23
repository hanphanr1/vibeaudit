export async function POST(request) {
  const event = await request.json();
  return store.record(event.type);
}
