# Brief: AI assistant HTML reports with email delivery

Received from the product owner on 2026-11-22. Build right after step AI-3, as step AI-R, before AI-4.

## Product owner's request (verbatim)

> do one more thing if any one ask for generate report on the ai assistant then generate report in html and render on the chatbot
> and also anybody say send this report on my email then send the same generate html on there email or provided email
> also when generate html report make sure include multime graph, pie chart, bar chart, table so it should look like proper dashbord

## Scope

1. **Generate.** "Generate a security report" (optionally for a period, an organization scope or a module) produces a dashboard-style HTML report shown inside the chat.
   - Summary cards.
   - Several line or area charts: mail volume and threat verdicts over time.
   - Pie or donut charts: verdict mix, threat types.
   - Bar charts: top senders, top targeted users, policies hit, quarantine reasons.
   - Tables.
   - Every figure comes from existing report and statistics APIs, called with the user's own permissions through the assistant's loopback tools. The model never invents or estimates numbers.
2. **Render in chat.** Charts are rendered server-side as static SVG inside self-contained HTML, with no scripts and no external resources. It is shown in a sandboxed iframe (srcdoc, no allow-scripts) with an "Open full size" view.
3. **Email.** "Send this report to my email" or "send it to name@example.com" emails the same HTML through the existing notification mailer. It is a write action through the AI-2 confirmation flow and is audited.
4. **Recipient rule (product-owner decision 2026-11-22: safe default).** Allowed recipients:
   - the signed-in user's own address;
   - users of the same organization;
   - addresses in the organization's verified domains.
     Any other external address is refused (exfiltration guard).
5. **Limits and audit.** Each generation and send is audited. Daily email limits apply per user and per tenant, and so do size limits.
6. **Storage.** Report HTML lives in object storage, not MySQL, and follows the conversation retention.
7. **Rules.** Same as the program:
   - tenant isolation and RBAC through existing APIs;
   - no email bodies or attachments in reports;
   - untrusted data stays escaped (no HTML injection from mail-derived strings);
   - tests use the fake provider and a local SMTP sink only.
