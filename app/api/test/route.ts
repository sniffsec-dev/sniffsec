import { cookies } from 'next/headers'; export async function GET() { const c = cookies(); return new Response('hi'); }
