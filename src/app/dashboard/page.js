import { redirect } from 'next/navigation';

export default function DashboardHome() {
  redirect('/user-dashboard');
}
