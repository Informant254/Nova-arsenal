'use client';

import { useEffect, useState } from 'react';

interface ScopeEntry {
  id: number;
  target: string;
  description: string;
  is_wildcard: boolean;
  created_at: string;
}

export default function ScopePage() {
  const [scope, setScope] = useState<ScopeEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [newTarget, setNewTarget] = useState('');
  const [description, setDescription] = useState('');

  useEffect(() => {
    // TODO: Fetch scope from API
    setScope([]);
    setLoading(false);
  }, []);

  const handleAdd = async () => {
    if (!newTarget.trim()) return;
    
    // TODO: Add scope via API
    setNewTarget('');
    setDescription('');
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold text-nova-600 mb-8">Scope Management</h1>
        
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Add Target</h2>
          <div className="flex gap-4">
            <input
              type="text"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              placeholder="example.com or *.example.com"
              className="flex-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-nova-500 focus:border-nova-500"
            />
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (optional)"
              className="flex-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-nova-500 focus:border-nova-500"
            />
            <button
              onClick={handleAdd}
              className="bg-nova-600 text-white px-6 py-2 rounded-md hover:bg-nova-700"
            >
              Add
            </button>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Target
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Description
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Added
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {scope.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-gray-500">
                    No targets in scope
                  </td>
                </tr>
              ) : (
                scope.map((entry) => (
                  <tr key={entry.id}>
                    <td className="px-6 py-4 whitespace-nowrap font-mono">
                      {entry.target}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                      {entry.description || '—'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        entry.is_wildcard ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'
                      }`}>
                        {entry.is_wildcard ? 'Wildcard' : 'Exact'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(entry.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button className="text-red-600 hover:text-red-800 text-sm">
                        Remove
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
