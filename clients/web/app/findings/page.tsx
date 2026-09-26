import { redirect } from 'next/navigation';

export default function LegacyWorkspaceRedirect() {
  redirect('/sessions');
}
