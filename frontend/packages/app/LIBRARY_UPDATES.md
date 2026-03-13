# Hashi Component Library Updates

Changes made in the frontend app that diverge from the component library (`hashi-library`).
Use this to track what needs to be upstreamed or reconciled.

---

## Atoms

### 1. Icon — New icons added

**File:** `components/atoms/Icon/icons.tsx`

Added `LinkBreak` (broken-link SVG) and `Wallet` (wallet SVG with filled clasp dot) icons to the registry.

---

### 2. InputValue — Validation, max balance, and currency-aware

**File:** `components/atoms/InputValue/InputValue.tsx`

- Changed `currency` prop type from open `string` to `'BTC' | 'suiBTC'`
- Added `maxValue` prop — when provided, shows wallet icon + balance + clickable "Max" pill
- Added input validation: `handlePaste` strips non-numeric chars, `handleChange` normalizes decimals, `handleKeyDown` blocks invalid keys
- Default icon resolved dynamically from `currency` prop instead of hardcoded

---

### 3. InputWallet — Connected wallet mode

**File:** `components/atoms/InputWallet/InputWallet.tsx`

- Added `connectedAddress` prop for read-only display of connected wallet
- When `connectedAddress` is set: shows truncated address with green checkmark, hides editable input
- When unset: original editable `contentEditable` input behavior
- Added `isConnect` prop to conditionally show "Connect Wallet" button
- Added `formatAddress()` helper for `0x1234...abcd` truncation

---

### 4. PageLayout — Wallet props changed

**File:** `components/atoms/PageLayout/PageLayout.tsx`

- Removed `onUsernameClick` prop, replaced with `onDisconnect`
- Added `address` prop (passes full `account.address` to Header)
- Removed unused `Button` import

---

### 5. Tabs — Icon name casing fix

**File:** `components/atoms/Tabs/Tabs.tsx`

- Fixed `<Icon name="SuiBTC" />` to `<Icon name="suiBTC" />` to match icon registry

---

## Molecules

### 6. TransactionConfirmations — BTC receiving row

**File:** `components/molecules/TransactionConfirmations/TransactionConfirmations.tsx`

- Added optional `btcReceiving` prop
- When provided, renders a separator line and a row showing BTC icon with the receiving amount

---

### 7. TransactionProgress — Current step + amounts

**File:** `components/molecules/TransactionProgress/TransactionProgress.tsx`

- Added `'current'` to `ProgressStep.status` union (was `'pending' | 'success' | 'error'`)
- Added `amount` and `currency` optional fields to `ProgressStep`
- `current` step renders with brighter white ring; label is bold and appends `— {amount} {currency}` when present

---

### 8. TransferDetails — Functional copy button

**File:** `components/molecules/TransferDetails/TransferDetails.tsx`

- Added `copyValue` optional prop (allows copying a different value than the displayed text)
- Integrated `useCopyToClipboard` hook — copy button now actually works
- Copy feedback: swaps Copy icon for green Check icon after copying

---

### 9. TransferForm — Wallet integration + balance display

**File:** `components/molecules/TransferForm/TransferForm.tsx`

- Integrated `useCurrentAccount` and `ConnectModal` from `@mysten/dapp-kit`
- Removed `onConnectWallet` prop — wallet connection handled internally via `ConnectModal`
- Tab-aware currency: switches BTC/suiBTC icon and label based on receive/withdraw tab
- Added `useHbtcBalance` hook — shows suiBTC balance + Max button on withdraw tab
- Passes `connectedAddress` to `InputWallet`; falls back to manual entry
- Submit uses connected address when available (`account?.address ?? wallet`)

---

## Organisms

### 10. Header — Account dropdown menu

**File:** `components/organisms/Header/Header.tsx`

- Replaced `onUsernameClick` with `address` + `onDisconnect` props
- Added dropdown menu on username button click with:
  - **Copy Address** — copies full address, shows "Copied!" with check icon (2s timeout)
  - **Disconnect** — calls `onDisconnect`
- Added click-outside detection to close dropdown

---

## Pages

### 11. HomePage — Tab-aware routing

**File:** `components/pages/HomePage/HomePage.tsx`

- Routes to `/withdraw` or `/deposit` based on selected tab (was always `/review`)
- Passes `amount`, `wallet`, and `usdValue` in navigation state

---

## New Components (not in library)

These components were created for the app and don't exist in `hashi-library`:

- **`QRCode`** — QR code renderer for deposit addresses
- **`InputConnect`** — Wallet connection input variant
- **`TransferSummary`** — Transfer amount display with currency icon and optional status
- **`DepositPage`** — Full deposit flow (address generation, txid input, vout lookup, status tracking)
- **`WithdrawPage`** — Full withdrawal flow (BTC address input, submit request, status tracking)
