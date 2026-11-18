import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { verifyToken } from '../lib/auth';

export default async function Home() {
  const cookieStore = await cookies();
  const userToken = cookieStore.get('auth-token')?.value;
  const adminToken = cookieStore.get('admin-token')?.value;

  if (userToken) {
    const decoded = verifyToken(userToken);
    if (decoded && decoded.userId) {
      redirect('/user-dashboard');
    }
  }

  if (adminToken) {
    redirect('/admin/dashboard');
  }

  redirect('/login');
}
