import React from 'react';
import { AuthMemoryProvider } from './context/AuthMemoryContext';
import { VaultDashboard } from './components/VaultDashboard';

export const App: React.FC = () => {
  return (
    <AuthMemoryProvider>
      <VaultDashboard />
    </AuthMemoryProvider>
  );
};

export default App;
