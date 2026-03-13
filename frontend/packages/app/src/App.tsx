import { BrowserRouter, Routes, Route } from 'react-router-dom';

import { HomePage } from '@/components/pages/HomePage/HomePage';
import { DepositPage } from '@/components/pages/DepositPage/DepositPage';
import { WithdrawPage } from '@/components/pages/WithdrawPage/WithdrawPage';
import { TransactionHistoryPage } from '@/components/pages/TransactionHistoryPage/TransactionHistoryPage';

function App() {
	return (
		<BrowserRouter>
			<Routes>
				<Route path="/" element={<HomePage />} />
				<Route path="/deposit" element={<DepositPage />} />
				<Route path="/deposit/:txDigest" element={<DepositPage />} />
				<Route path="/withdraw" element={<WithdrawPage />} />
				<Route path="/withdraw/:txDigest" element={<WithdrawPage />} />
				<Route path="/history" element={<TransactionHistoryPage />} />
			</Routes>
		</BrowserRouter>
	);
}

export default App;
