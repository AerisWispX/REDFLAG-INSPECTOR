import { Rule } from "./types";

export interface CategoryDefinition {
  id: string;
  name: string;
  description: string;
  weight: number;
  rules: Rule[];
}

export const CATEGORIES: CategoryDefinition[] = [
  {
    id: "payment",
    name: "Payment & Deposit Demands",
    description: "Upfront fees, equipment purchase demands, untraceable transfer methods, or altered payment accounts.",
    weight: 32,
    rules: [
      {
        id: "p1",
        title: "Refundable / registration fee requested",
        points: 30,
        explanation: "Scammers frequently disguise advance-fee fraud as refundable deposits, onboarding charges, or processing fees.",
        pattern: /\b(registration|processing|security|refundable|admin(?:istration)?|verification|training|joining)\s+(?:fee|deposit|charge)\b/i,
      },
      {
        id: "p2",
        title: "Told to buy your own equipment first",
        points: 26,
        explanation: "Legitimate employers provide required work equipment directly; directing you to buy equipment or software through an 'approved vendor' is a classic advance-fee scam.",
        pattern: /\b(purchase|buy)\s+(?:your(?:\s+own)?\s+)?(?:equipment|laptop|kit|software license|starter kit)\b/i,
      },
      {
        id: "p3",
        title: "Payment via gift card, crypto, or wire service",
        points: 28,
        explanation: "Requests for payment via non-recoverable or semi-anonymous payment channels like gift cards, cryptocurrency, Western Union, MoneyGram, or Zelle.",
        pattern: /\b(gift card|bitcoin|crypto(?:currency)?|western union|moneygram|wire transfer|zelle|venmo(?: only)?)\b/i,
      },
      {
        id: "p4",
        title: "Deposit demanded before viewing / verifying",
        points: 26,
        explanation: "Demanding money to hold or reserve an apartment before an in-person walkthrough or background check verification.",
        pattern: /\b(hold|reserve|secure)\s+the\s+(?:unit|apartment|property|room)\b.{0,40}\b(pay|wire|send|deposit)\b|deposit\s+(?:before|prior to)\s+(?:viewing|seeing|visiting)/is,
      },
      {
        id: "p5",
        title: "Out-of-country / can't-show-it story",
        points: 18,
        explanation: "Excuses claiming inability to meet or show a rental property in person due to overseas travel, military deployment, or emergency.",
        pattern: /\b(out of (?:the )?country|currently (?:abroad|overseas|traveling)|can'?t (?:show|meet) (?:it|you) in person)\b/i,
      },
      {
        id: "p6",
        title: "Bank/payment details “recently changed”",
        points: 30,
        explanation: "Sudden notice of updated payment accounts or instructions to route funds to an alternate account is typical of payment redirection fraud.",
        pattern: /\b(updated (?:our )?(?:bank|payment|account) details|new (?:bank|account) details|please use (?:this|the) (?:new )?account (?:for|to) (?:payment|deposit))\b/i,
      },
      {
        id: "p7",
        title: "Cuota de registro / depósito reembolsable (Spanish)",
        points: 30,
        explanation: "Spanish-language equivalent of p1: a registration fee or refundable deposit demanded to 'confirm' or 'process' an applicant.",
        pattern: /\b(cuota de (?:registro|inscripci[oó]n|administraci[oó]n|verificaci[oó]n|capacitaci[oó]n)|dep[oó]sito reembolsable)\b/i,
      },
      {
        id: "p8",
        title: "Pago con tarjeta de regalo, criptomoneda o transferencia (Spanish)",
        points: 28,
        explanation: "Spanish-language equivalent of p3: payment demanded via gift card, cryptocurrency, or an untraceable wire service.",
        pattern: /\b(tarjeta de regalo|criptomoneda|transferencia bancaria)\b|\b(western union|moneygram)\b/i,
      },
    ],
  },
  {
    id: "urgency",
    name: "Urgency & Pressure Tactics",
    description: "Artificial deadlines, limited slots, or pressure to transfer funds immediately before verifying facts.",
    weight: 16,
    rules: [
      {
        id: "u1",
        title: "Artificial deadline / expiring offer",
        points: 55,
        explanation: "Creating artificial urgency (expiring today, limited slots, 24-hour limit) to induce impulsive action without due diligence.",
        pattern: /\b(expires? (?:today|tonight|in \d+ hours?)|limited slots?|within 24 hours|act (?:now|immediately|fast)|respond (?:immediately|urgently))\b/i,
      },
      {
        id: "u2",
        title: "Pressure to pay same-day",
        points: 45,
        explanation: "Aggressive demand to submit deposit or payment right away or on the same calendar day.",
        pattern: /\b(today|immediately|right away|asap)\b.{0,25}\b(pay|payment|deposit|transfer|send)\b/i,
      },
      {
        id: "u3",
        title: "Oferta expira hoy / cupos limitados (Spanish)",
        points: 50,
        explanation: "Spanish-language equivalent of u1: manufactured scarcity or urgency language designed to prevent verification.",
        pattern: /\b(expira hoy|cupos limitados|responda (?:de inmediato|urgentemente)|act[uú]e (?:ahora|de inmediato))\b/i,
      },
    ],
  },
  {
    id: "channel",
    name: "Contact Channel Red Flags",
    description: "Unprofessional communication channels, free email domains, or avoiding traceable contact methods.",
    weight: 16,
    rules: [
      {
        id: "c1",
        title: "Personal email domain for official business",
        points: 45,
        explanation: "Corporate recruiters and established property management firms communicate from company domains, not free public webmail addresses.",
        pattern: /@(gmail|yahoo|outlook|hotmail|aol|icloud)\.com\b/i,
      },
      {
        id: "c2",
        title: "Pushed to WhatsApp / Telegram",
        points: 40,
        explanation: "Directing communications to encrypted messaging apps like WhatsApp or Telegram away from monitored company channels or job portals.",
        pattern: /\b(whatsapp|telegram|signal)\b.{0,30}(\+?\d[\d\-\s]{7,}\d|@\w)/i,
      },
      {
        id: "c3",
        title: "No official phone or verifiable office contact",
        points: 15,
        explanation: "Explicit instruction that no phone contact is available or insistence on communicating strictly via unofficial channels.",
        pattern: /\b(no phone|do not call|contact (?:only|us only) (?:by|via) email|email only)\b/i,
      },
    ],
  },
  {
    id: "credential",
    name: "Credential & Identity Harvesting",
    description: "Demands for sensitive identity numbers, bank logins, or suspicious login verification links.",
    weight: 14,
    rules: [
      {
        id: "h1",
        title: "Asked to share a government ID or SSN early",
        points: 40,
        explanation: "Premature requests for sensitive identification (SSN, national ID, passport, or driver license scans) before official onboarding.",
        pattern: /\b(social security number|ssn|passport (?:number|copy|scan)|driver\'?s licen[sc]e (?:number|copy|scan)|national id)\b/i,
      },
      {
        id: "h2",
        title: "Asked for bank login or card details directly",
        points: 45,
        explanation: "Direct solicitation of banking credentials, passwords, card numbers, PINs, or CVV codes.",
        pattern: /\bbank\b.{0,20}\b(login|username|password)\b|\bcard (?:number and )?(?:pin|cvv)\b/i,
      },
      {
        id: "h3",
        title: "Asked to click a link to verify or log in",
        points: 30,
        explanation: "Urging user to click an external verification link to login or confirm account details, indicative of credential harvesting.",
        pattern: /\bclick here\b.{0,20}\b(verify|login|log ?in|sign ?in|access|confirm)\b|\bhere to (?:verify|log ?in|sign ?in|confirm|access)\b/i,
      },
      {
        id: "h4",
        title: "Solicitud de número de seguro social o identificación (Spanish)",
        points: 40,
        explanation: "Spanish-language equivalent of h1: premature request for a government ID, passport, or national identification number.",
        pattern: /\b(n[uú]mero de seguro social|copia de (?:su )?(?:pasaporte|identificaci[oó]n|licencia de conducir))\b/i,
      },
      {
        id: "h5",
        title: "Solicitud de contraseña bancaria o número de cuenta (Spanish)",
        points: 40,
        explanation: "Spanish-language equivalent of h2: direct solicitation of banking credentials or card details.",
        pattern: /\bcontrase[nñ]a\s+(?:de\s+)?(?:banco|bancaria)\b|\bn[uú]mero de cuenta y (?:pin|cvv)\b/i,
      },
    ],
  },
  {
    id: "identity",
    name: "Identity & Personalization Gaps",
    description: "Generic salutations, lack of named corporate point of contact, or unrealistically low requirements for high compensation.",
    weight: 10,
    rules: [
      {
        id: "i1",
        title: "Generic, non-personalized greeting",
        points: 42,
        explanation: "Impersonal mass-blasted opening ('Dear Candidate', 'Dear Applicant', 'Dear Sir/Madam') lacking your personal name.",
        pattern: /\b(dear (?:candidate|applicant|sir\/?madam|sir or madam|user|customer)|to whom it may concern)\b/i,
      },
      {
        id: "i2",
        title: "No named point of contact or role",
        points: 20,
        explanation: "Closing signed with only a generic group title ('HR Team', 'The Landlord', 'Recruitment Department') without an individual verified name.",
        pattern: /\b(hr team|the (?:landlord|hiring team|management)|recruitment (?:team|department))\s*[,.]?\s*$/im,
      },
      {
        id: "i3",
        title: "No experience needed for high pay",
        points: 26,
        explanation: "High compensation paired with explicitly zero requirements or qualifications, designed as clickbait for job seekers.",
        pattern: /\bno experience (?:required|needed|necessary)\b/i,
      },
      {
        id: "i4",
        title: "Saludo genérico y no personalizado (Spanish)",
        points: 40,
        explanation: "Spanish-language equivalent of i1: a generic, mass-template greeting rather than one addressed to you by name.",
        pattern: /\b(estimado(?:\/a)? candidato|estimado(?:\/a)? solicitante|a quien corresponda)\b/i,
      },
      {
        id: "i5",
        title: "No se requiere experiencia para alto salario (Spanish)",
        points: 26,
        explanation: "Spanish-language equivalent of i3: high pay combined with an explicit no-experience-needed lure.",
        pattern: /\bno se requiere experiencia\b/i,
      },
    ],
  },
  {
    id: "impersonation",
    name: "Brand & Platform Impersonation",
    description: "A sender or link domain that closely resembles a well-known employer, job board, or rental platform — a classic typosquat.",
    weight: 8,
    // No regex rules here: this category is populated by a dedicated
    // domain-similarity check (src/lib/typosquat.ts) run against every
    // email/URL domain found in the text, not a pattern over raw text —
    // see scanText() in scoring.ts.
    rules: [],
  },
  {
    id: "language",
    name: "Language & Formatting Anomalies",
    description: "Extreme urgency punctuation, excessive uppercase words, or generic congratulations template text.",
    weight: 2,
    rules: [
      {
        id: "l1",
        title: "Excessive urgency punctuation",
        points: 30,
        explanation: "Repeated exclamation points or long strings of ALL-CAPS words used to manufacture excitement or alarm.",
        pattern: /(!\s*!|[A-Z]{6,}\s+[A-Z]{6,})/,
      },
      {
        id: "l2",
        title: "Vague, templated congratulations",
        points: 24,
        explanation: "Vague immediate congratulations for being selected or shortlisted without preceding interview stages.",
        pattern: /\bcongratulations!?\s+you (?:have been|'ve been) (?:shortlisted|selected|chosen)\b/i,
      },
    ],
  },
  {
    id: "link",
    name: "Link & Domain Structure",
    description: "URL shorteners, unencrypted HTTP links, raw IP addresses, or suspicious high-risk top level domains.",
    weight: 2,
    rules: [
      {
        id: "k1",
        title: "Link uses a URL shortener",
        points: 40,
        explanation: "Obfuscated target destination using link shortening services like bit.ly, tinyurl, or is.gd to conceal phishing URLs.",
        pattern: /\b(bit\.ly|tinyurl\.com|is\.gd|t\.co|goo\.gl|cutt\.ly|rebrand\.ly)\/\S+/i,
      },
      {
        id: "k2",
        title: "No HTTPS on a link",
        points: 30,
        explanation: "Unencrypted plain HTTP links in an email or message requesting credentials or interaction.",
        pattern: /\bhttp:\/\/\S+/i,
      },
      {
        id: "k3",
        title: "Raw IP address used as a link",
        points: 45,
        explanation: "Direct IP address navigation bypassing standard domain registration, heavily associated with malicious hosting.",
        pattern: /\bhttps?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      },
      {
        id: "k4",
        title: "Suspicious top-level domain",
        points: 35,
        explanation: "Link utilizes top-level domains frequently abused by phishing campaigns (e.g. .xyz, .top, .tk, .click, .support, .work, .live).",
        pattern: /\bhttps?:\/\/[^\s]+\.(xyz|top|tk|click|support|work|live|rest)(\/|\s|$)/i,
      },
    ],
  },
];
