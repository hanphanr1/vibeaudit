'use server';
export async function saveOrder(order) { return db.orders.create(order); }
