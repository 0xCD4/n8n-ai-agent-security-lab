# Multi-workflow map launch copy

## LinkedIn — English

I’ve been looking at a blind spot in n8n security reviews: workflows are usually scanned one JSON file at a time, even when the real permission path crosses several workflows.

I added a multi-workflow trust-boundary map to my open-source n8n security lab. It reads a directory of exports together, resolves Execute Sub-workflow and Call n8n Workflow Tool references, and shows when public input or model output can reach a credentialed action in another workflow without a visible approval step.

I tested it against a pinned public GitHub snapshot: 24 workflows, 297 nodes, and 8 sub-workflow calls. Five calls resolved, three needed manual review, and the scanner surfaced two high-priority cross-workflow review paths.

That does not mean I found two vulnerabilities. These are static review signals: places where a human should inspect the credential scope and approval boundary. Nothing was imported, activated, or executed, and raw workflow and credential IDs were not published.

Code: https://github.com/0xCD4/n8n-ai-agent-security-lab

Method and data source: https://github.com/0xCD4/n8n-ai-agent-security-lab/blob/main/research/multi-workflow-study/public-repo-snapshot/summary.md

If you use sub-workflows in production, I’d be interested to hear which boundary is hardest to review: credentials, approvals, or dynamic workflow targets?

## X / Twitter — Turkish

### 1/2

n8n workflow’larını tek tek taramak aralarındaki yetki zincirini göstermiyor.

Bu yüzden aracıma multi-workflow trust-boundary map ekledim. Sub-workflow çağrılarını çözüyor; credential reuse, approval eksikleri ve dinamik hedefleri incelemeye çıkarıyor.

https://github.com/0xCD4/n8n-ai-agent-security-lab

### 2/2

Gerçek bir public snapshot’ta 24 workflow ve 297 node tarandı. 8 çağrının 5’i çözüldü, 3’ü incelemeye kaldı. İki high-priority cross-workflow path görüldü.

Bunlar açık iddiası değil. Workflow’lar çalıştırılmadı; ham credential ve workflow ID’leri yayımlanmadı.

## X / Twitter — English

### 1/2

I’ve added a multi-workflow trust-boundary map to my n8n security lab.

It resolves sub-workflow calls and surfaces credential reuse, missing approval boundaries, and dynamic targets across exported workflows.

https://github.com/0xCD4/n8n-ai-agent-security-lab

### 2/2

Tested on a pinned public snapshot: 24 workflows, 297 nodes, 8 calls. Five resolved, three needed review, and two high-priority cross-workflow paths surfaced.

Static review signals, not vulnerability claims. Nothing was imported or executed; raw IDs were not published.
