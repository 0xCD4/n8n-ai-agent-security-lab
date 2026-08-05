# Fable 5 market-gap research prompt

> Research snapshot: this prompt tested the former EUR 29 / EUR 59 hypothesis. It is retained as research input, not as the current commercial offer. The current pilot is documented in `SERVICE.md`.

Copy everything below into Fable 5. Give it web access if available.

---

You are an adversarial product researcher and practical security-services operator. I do not want generic SaaS ideas, motivational advice, an SEO listicle, or a claim that a market has no competitors. I want one narrow offer that a real buyer could pay for within 14 days.

Research the current internet before answering. Use dated, direct links to primary sources wherever possible: current marketplace listings, public job posts, official product pricing, vendor documentation, agency service pages, public procurement requests, or first-party customer discussions. Mark inaccessible or uncertain evidence as UNKNOWN. Do not invent demand, customers, prices, acceptance, or technical capabilities.

Project context:

- Public product: https://en.csintresearch.org/ai-security
- Public repository: https://github.com/0xCD4/n8n-ai-agent-security-lab
- Existing capabilities: local static review of exported n8n workflows; untrusted-input, webhook, model-to-action, human-approval, credential-type, outbound-domain, validation, timeout, retry, audit and error-path findings; baseline-versus-candidate change review; SHA-256-bound reports; JSON, Markdown, SARIF, Mermaid, SVG and print outputs; optional customer-controlled staging contracts and receipts.
- Privacy boundary: raw workflows, reports and contracts remain on the customer's device unless the customer deliberately shares a generated report or screen. No production credentials or unauthorized testing.
- Current commercial hypothesis: EUR 29 Quick Check for one workflow up to 20 active nodes, or EUR 59 Release Check for a baseline-versus-candidate comparison up to 40 active nodes.
- Preferred initial ticket: EUR 20 to EUR 150. International English-speaking buyers are acceptable.
- The founder can deliver technical work in English or Turkish and can use n8n, JavaScript, Python, Cloudflare Workers, OSINT and defensive security analysis.

Your job is to try to disprove the current offer and find a better under-served wedge if one exists. Under-served means the buyer problem and payment signal are visible, while current offers solve it poorly or bundle it into expensive consulting. It does not mean "no competitors."

Research these buyer groups separately:

1. n8n agencies handing workflows to clients.
2. Internal teams maintaining versioned n8n workflows.
3. Freelancers asked to repair, harden or document an existing workflow.
4. Small security or compliance teams reviewing AI-enabled automations.

Required output:

1. **Reality check:** Is the EUR 29 / EUR 59 assisted review likely to receive a first paid order? Give a yes, no, or uncertain verdict and the strongest evidence against it.
2. **Demand evidence table:** At least 12 current pieces of evidence with date, buyer type, exact pain, transaction signal, source URL, and confidence. Separate "people discuss this" from "people pay for this."
3. **Competition matrix:** At least 8 direct or adjacent alternatives. Include their exact offer, current price if public, buyer, strengths, gaps, and why our offer would or would not win. Include n8n's own security audit and workflow-diff capabilities.
4. **Three narrow wedges:** Each must be deliverable using the existing capabilities or no more than three focused implementation days. For each, provide buyer, trigger event, concrete deliverable, privacy boundary, introductory fixed price, delivery time, and likely acquisition channel.
5. **One recommendation:** Select exactly one wedge. Explain why it beats the other two and the current generic audit positioning.
6. **Offer copy:** Provide a plain-English marketplace title, 120-word description, two fixed-price packages, buyer requirements, exclusions, and one short proposal. Avoid hype, fear language, fake scarcity, and AI-sounding copy.
7. **Fourteen-day validation plan:** Maximum two hours of work per day. Define exact daily actions, the number of proposals or verified contacts, and stop/change criteria. Do not recommend building more features before payment evidence.
8. **Failure pre-mortem:** List the five most likely reasons nobody buys and the cheapest test for each.
9. **Evidence gaps:** State what cannot be concluded from public internet research and what must be learned from actual paid or rejected offers.

Hard constraints:

- Defensive, authorized and legal work only.
- Never recommend receiving production secrets or attacking a live system.
- Do not say "unique," "first," "only," or "no competitors" without verifiable proof.
- Do not treat GitHub stars, likes, replies, or free users as revenue validation.
- Do not propose a broad platform, course, newsletter, ad business, or generic AI agency.
- Do not hide behind "talk to users." Provide the exact offer and exact validation actions.
- Prefer a painful release, handoff, repair, evidence or governance task over another scanner subscription.
- Cite every time-sensitive market or pricing claim with a direct URL.

Be skeptical. If the current project is technically strong but commercially weak, say so clearly and identify the smallest sellable outcome.

---
