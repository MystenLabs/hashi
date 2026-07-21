// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Custom docs landing page, modeled on the docs.sui.io homepage: a hero with
// title/tagline and calls to action, followed by grouped grids of section
// cards. Lives at the site root ('/'); the Introduction doc moved to
// '/introduction'.

import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './index.module.css';

/** Inline token chip: official coin icon + ticker, matching the Hashi app. */
function Token({ icon, label }: { icon: string; label: string }) {
  return (
    <span className={styles.token}>
      <img
        className={styles.tokenIcon}
        src={useBaseUrl(`/img/${icon}`)}
        alt=""
        aria-hidden="true"
        width={20}
        height={20}
      />
      {label}
    </span>
  );
}

interface CardItem {
  title: string;
  href: string;
  description: string;
}

interface CardSection {
  title: string;
  subtitle: string;
  items: CardItem[];
}

const SECTIONS: CardSection[] = [
  {
    title: 'Learn the basics',
    subtitle: 'Understand what Hashi does and how BTC moves through it.',
    items: [
      {
        title: 'Introduction',
        href: '/introduction',
        description:
          'What Hashi is and how it secures native BTC for use on Sui through threshold cryptography.',
      },
      {
        title: 'User Flows',
        href: '/user-flows',
        description:
          'The deposit and withdrawal flows end to end, from Bitcoin to hBTC on Sui and back.',
      },
      {
        title: 'Deposit',
        href: '/deposit',
        description:
          'How BTC sent to a deposit address becomes hBTC through the request, approve, confirm, and mint phases.',
      },
      {
        title: 'Withdraw',
        href: '/withdraw',
        description:
          'How burning hBTC on Sui redeems native BTC, with the committee signing the Bitcoin transaction through MPC.',
      },
    ],
  },
  {
    title: 'Protocol design',
    subtitle: 'How the committee custodies Bitcoin and governs itself onchain.',
    items: [
      {
        title: 'Committee',
        href: '/committee',
        description:
          'The validator set that collectively manages the Bitcoin master key. No single member holds it.',
      },
      {
        title: 'MPC Protocol',
        href: '/mpc-protocol',
        description:
          'Threshold Schnorr signing, distributed key generation, and per-epoch key rotation.',
      },
      {
        title: 'Guardian',
        href: '/guardian',
        description:
          'The independent policy service that screens committee actions before they finalize.',
      },
      {
        title: 'Governance Actions',
        href: '/governance-actions',
        description:
          'How members propose, vote on, and execute configuration and upgrade changes onchain.',
      },
      {
        title: 'Bitcoin Address Scheme',
        href: '/address-scheme',
        description:
          'How each Sui address maps to a unique Taproot Bitcoin deposit address.',
      },
      {
        title: 'Configuration',
        href: '/config',
        description:
          'The onchain protocol parameters that govern deposits, withdrawals, and pausing.',
      },
    ],
  },
  {
    title: 'Run a node',
    subtitle: 'For Sui validators joining the Hashi committee.',
    items: [
      {
        title: 'Node Operator Runbook',
        href: '/node-operator-runbook',
        description:
          'Prerequisites, configuration, key management, genesis, monitoring, and troubleshooting.',
      },
      {
        title: 'Node Backups',
        href: '/node-backup',
        description:
          'Encrypted per-epoch backups of MPC key shares and how to restore them, including with a YubiKey.',
      },
    ],
  },
  {
    title: 'Build',
    subtitle: 'Integrate Hashi into your own application.',
    items: [
      {
        title: 'TypeScript SDK',
        href: '/ts-sdk',
        description:
          'Construct deposit and withdrawal transactions and query Hashi state from TypeScript.',
      },
    ],
  },
];

function Hero() {
  return (
    <header className={styles.hero}>
      <div className={styles.heroInner}>
        <h1 className={styles.heroTitle}>Hashi Documentation</h1>
        <p className={styles.heroTagline}>
          Hashi is the Sui native Bitcoin orchestrator. Deposit native{' '}
          <Token icon="btc.svg" label="BTC" />, mint{' '}
          <Token icon="hbtc.svg" label="hBTC" /> on Sui, and put your Bitcoin to
          work in DeFi. A validator committee running threshold cryptography
          secures the underlying Bitcoin.
        </p>
      </div>
    </header>
  );
}

function SectionGrid({ section }: { section: CardSection }) {
  return (
    <section className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}>{section.title}</h2>
        <p className={styles.sectionSubtitle}>{section.subtitle}</p>
      </div>
      <div className={styles.cardGrid}>
        {section.items.map((item) => (
          <Link key={item.href} className={styles.card} to={item.href}>
            <h3 className={styles.cardTitle}>
              {item.title}
              <span className={styles.cardArrow} aria-hidden="true">
                →
              </span>
            </h3>
            <p className={styles.cardCopy}>{item.description}</p>
          </Link>
        ))}
      </div>
    </section>
  );
}

export default function Home() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title="Documentation"
      description={siteConfig.tagline}
    >
      <main className={styles.main}>
        <Hero />
        <div className={styles.sections}>
          {SECTIONS.map((section) => (
            <SectionGrid key={section.title} section={section} />
          ))}
        </div>
      </main>
    </Layout>
  );
}
