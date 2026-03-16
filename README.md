# 💸 RupeeLink

> **P2P INR ↔ USDC Trading Platform on Monad Testnet**

[![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript)](https://typescriptlang.org)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8-363636?style=flat-square&logo=solidity)](https://soliditylang.org)
[![Deployed on Vercel](https://img.shields.io/badge/Deployed-Vercel-000?style=flat-square&logo=vercel)](https://rupeelink.vercel.app)
[![Monad Testnet](https://img.shields.io/badge/Network-Monad%20Testnet-6366F1?style=flat-square)](https://monad.xyz)

RupeeLink lets users trade Indian Rupees for USDC stablecoins peer-to-peer — no centralized exchange needed. Buyers pay via Razorpay (UPI/IMPS/NEFT) and receive USDC directly to their wallet through a Solidity escrow smart contract on Monad Testnet.

🔗 **Live:** [rupeelink.vercel.app](https://rupeelink.vercel.app) &nbsp;|&nbsp; 📄 **Contract:** [`0x736d728451D0E6d649373c533269317EDb68710c`](https://testnet.monadexplorer.com/address/0x736d728451D0E6d649373c533269317EDb68710c)

---

## ✨ Features

- **P2P Escrow** — Seller locks USDC in contract; funds release only after verified INR payment
- **Razorpay Integration** — UPI, IMPS, NEFT, bank transfer support
- **Non-Custodial** — Users retain full wallet ownership; private keys never touch the server
- **Clerk Auth** — Seamless sign-up/login with wallet address linkage
- **Real-time Trade Status** — `OPEN → PAYMENT_PENDING → COMPLETED`
- **Monad Testnet** — EVM-compatible, high throughput, low fees

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 16, TypeScript 5, App Router |
| Styling | Tailwind CSS, shadcn/ui, Framer Motion |
| Auth | Clerk |
| Blockchain | ethers.js v6, Solidity, Monad Testnet |
| Database | Prisma ORM + Neon PostgreSQL |
| Payments | Razorpay SDK |
| Deployment | Vercel |

---

## 🔄 How It Works

```
Seller deposits USDC → Contract locks funds
        ↓
Buyer initiates trade + pays INR via Razorpay
        ↓
Backend verifies Razorpay webhook (payment_captured)
        ↓
Smart contract releases USDC to buyer's wallet
        ↓
Trade record updated in PostgreSQL
```

---

## 📁 Project Structure

```
rupeelink/
├── app/
│   ├── (auth)/          # Clerk auth pages
│   ├── api/
│   │   ├── trades/      # Trade CRUD endpoints
│   │   ├── razorpay/    # Payment creation & webhook
│   │   └── contract/    # Smart contract interactions
│   ├── dashboard/       # User dashboard
│   ├── trades/          # Trade listings & detail
│   └── page.tsx         # Landing page
├── components/          # Reusable UI (shadcn/ui)
├── contracts/
│   └── RupeeLink.sol    # Escrow smart contract
├── lib/
│   ├── prisma.ts        # Prisma client singleton
│   ├── ethers.ts        # ethers.js helpers
│   └── razorpay.ts      # Razorpay SDK wrapper
├── prisma/
│   └── schema.prisma    # Database schema
└── package.json
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- MetaMask (connected to Monad Testnet)
- Razorpay test account
- Clerk account
- Neon PostgreSQL project

### Installation

```bash
git clone https://github.com/hsay123/RupeeLink.git
cd RupeeLink
npm install
cp .env.example .env.local   # fill in your values
npx prisma generate
npx prisma db push
npm run dev
```

> **Always run `npm run build` locally before pushing to Vercel.**

---

## 🔑 Environment Variables

```env
# Clerk
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=
CLERK_SECRET_KEY=

# Database
DATABASE_URL=

# Razorpay
RAZORPAY_KEY_ID=
RAZORPAY_KEY_SECRET=
NEXT_PUBLIC_RAZORPAY_KEY_ID=
RAZORPAY_WEBHOOK_SECRET=

# Blockchain
NEXT_PUBLIC_CONTRACT_ADDRESS=0x736d728451D0E6d649373c533269317EDb68710c
NEXT_PUBLIC_MONAD_RPC_URL=
```

---

## 📜 Smart Contract

- **Network:** Monad Testnet
- **Address:** `0x736d728451D0E6d649373c533269317EDb68710c`
- **Language:** Solidity `^0.8`
- **Model:** Seller deposits USDC → Buyer pays INR → Contract releases USDC

To redeploy:

```bash
npx hardhat run scripts/deploy.js --network monadTestnet
# Update NEXT_PUBLIC_CONTRACT_ADDRESS in .env.local
```

---

## 🗄 Database Schema

```prisma
model User {
  id         String   @id @default(cuid())
  clerkId    String   @unique
  walletAddr String?
  trades     Trade[]
}

model Trade {
  id              String      @id @default(cuid())
  sellerId        String
  buyerId         String?
  usdcAmount      Float
  inrAmount       Float
  status          TradeStatus
  razorpayOrderId String?
  txHash          String?
  createdAt       DateTime    @default(now())
}

enum TradeStatus { OPEN PAYMENT_PENDING COMPLETED CANCELLED }
```

---

## 🗺 Roadmap

- [x] P2P escrow smart contract
- [x] Razorpay INR payment integration
- [x] Clerk authentication + wallet linking
- [x] PostgreSQL trade tracking
- [ ] Dispute resolution mechanism
- [ ] User reputation & ratings
- [ ] Multi-stablecoin support (USDT, DAI)
- [ ] Monad mainnet deployment

---

## ⚠️ Known Issues

| Issue | Notes |
|-------|-------|
| Razorpay webhook retries | Add idempotency handling to prevent duplicate releases |
| Monad public RPC rate limits | Use a private RPC endpoint in production |
| No dispute mechanism | `payment_captured` webhook is currently the sole source of truth |

---

## 👤 Author

**Yash** · [github.com/hsay123](https://github.com/hsay123)

---

*Built on Monad Testnet. Not for production use with real funds.*
