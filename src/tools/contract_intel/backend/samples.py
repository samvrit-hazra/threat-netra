from typing import Dict, Any

SAMPLE_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "sample_a_restrictive": {
        "id": "sample_a_restrictive",
        "name": "StreamNova Enterprise Cloud MSA (Restrictive / High Risk)",
        "description": "Enterprise cloud services agreement containing auto-renewal traps, unilateral price hike clauses, and severe 50% early termination penalties.",
        "text": """[[PAGE 1]]
MASTER SERVICES AGREEMENT (ENTERPRISE EDITION)
Document Ref: SN-2026-ENT-A

Welcome to StreamNova Premium Enterprise Cloud Services.
1. SUBSCRIPTION FEES AND TERM COMMITMENT
1.1 The recurring cost is Rs. 999/month with a mandatory 12-month minimum initial term commitment.
1.2 Customer agrees to pay a mandatory one-time Rs. 500 setup fee upon signature. The setup fee is strictly non-refundable under all circumstances.
1.3 Invoices are payable net 15 days. Late payments accrue interest at 1.5% per month.

[[PAGE 2]]
2. SERVICE AVAILABILITY AND SERVICE LEVEL AGREEMENT (SLA)
2.1 StreamNova shall target 99.5% service uptime excluding scheduled maintenance windows.
2.2 Uptime calculations are performed on a monthly trailing aggregate. Customer must submit written SLA credit requests within 5 business days of incident closure.

[[PAGE 3]]
3. REFUNDS AND REMEDIES
3.1 Refunds are strictly restricted. Cash or bank refunds are never issued.
3.2 Service credits are only provided for confirmed total service outages exceeding 7 consecutive business days.
3.3 Customer waives rights to chargeback or claim damages for intermittent degradation.

[[PAGE 4]]
4. DATA OWNERSHIP AND TELEMETRY LOGS
4.1 Customer retains ownership of submitted primary records.
4.2 StreamNova reserves the right to aggregate, de-identify, and commercialize all system metadata, operational telemetry, and network query patterns.

[[PAGE 5]]
5. CONFIDENTIALITY AND SECURITY AUDIT
5.1 Each party shall safeguard proprietary data using reasonable industry standards.
5.2 StreamNova reserves the right to perform unannounced security audits of interconnected customer endpoints.

[[PAGE 6]]
6. INTELLECTUAL PROPERTY AND LICENSES
6.1 StreamNova grants a revocable, non-exclusive license during the active term.
6.2 Reverse engineering, benchmarking publication, or competitive testing is strictly prohibited.

[[PAGE 7]]
7. LIMITATION OF LIABILITY
7.1 StreamNova total cumulative liability for any breach or negligence is strictly capped at the fees paid in the immediately preceding 3 months.
7.2 In no event shall StreamNova be liable for consequential, punitive, or loss-of-data damages.

[[PAGE 8]]
8. TERM AND AUTOMATIC RENEWAL
8.1 The initial term is 12 months from the effective date.
8.2 Automatic Renewal: This contract auto-renews for successive 12-month terms at Rs. 1,199/month unless formal written cancellation notice is given at least 30 days before term end.
8.3 Price Escalation: StreamNova may unilaterally revise renewal pricing by up to 20% upon 15 days notice.

[[PAGE 9]]
9. SUSPENSION OF SERVICE
9.1 StreamNova may immediately suspend access without liability if customer account exceeds billing bandwidth quotas.
9.2 Reconnection requires payment of a Rs. 2,500 administrative reinstatement surcharge.

[[PAGE 10]]
10. INDEMNIFICATION OBLIGATIONS
10.1 Customer agrees to indemnify, defend, and hold harmless StreamNova from third-party IP infringement claims arising from uploaded customer data.

[[PAGE 11]]
11. EARLY TERMINATION AND LIQUIDATED DAMAGES
11.1 Either party may terminate for uncured material breach upon 30 days written notice.
11.2 Early Termination Fee: If customer terminates the agreement early for convenience, customer must immediately pay an early termination fee equal to 50% of remaining monthly fees for the unexpired term.

[[PAGE 12]]
12. GOVERNING LAW AND DISPUTE RESOLUTION
12.1 This agreement is governed by the laws of India. Jurisdiction is vested exclusively in the commercial courts of Mumbai.
"""
    },
    
    "sample_b_flexible": {
        "id": "sample_b_flexible",
        "name": "ClearConnect Flexible Cloud SLA (Transparent / Fair)",
        "description": "Transparent SaaS agreement featuring month-to-month flexibility, zero auto-renewal traps, pro-rated refunds, and no exit penalties.",
        "text": """[[PAGE 1]]
CLEARCONNECT SERVICES AGREEMENT (FLEXIBLE TIER)
Document Ref: CC-2026-FLEX-B

Welcome to ClearConnect Cloud Infrastructure.
1. PRICING AND BILLING TRANSPARENCY
1.1 Monthly price is Rs. 1,199/month for a 12-month term commitment.
1.2 There is no setup fee. Onboarding and technical provisioning are included without surcharge.
1.3 Taxes are clearly delineated on monthly itemized invoices.

[[PAGE 2]]
2. SERVICE UPTIME COMMITMENT
2.1 ClearConnect provides a 99.9% monthly uptime guarantee.
2.2 SLA credits are automatically calculated and credited toward subsequent invoices without requiring cumbersome manual claims.

[[PAGE 3]]
3. CANCELLATION AND REFUND POLICY
3.1 Requires a simple 7-day cancellation notice prior to the end of any billing cycle.
3.2 There is no early termination fee under any circumstances.
3.3 Customer may receive a pro-rated refund of unused prepaid fees within the first 30 days of onboarding.

[[PAGE 4]]
4. DATA PRIVACY AND SECURITY
4.1 All customer data remains strictly confidential and encrypted at rest and in transit (AES-256 / TLS 1.3).
4.2 ClearConnect does not sell, license, or analyze customer data or metadata for advertising or third-party training.

[[PAGE 5]]
5. MUTUAL LIABILITY
5.1 Mutual liability is capped at 12 months of fees paid under this agreement.
5.2 Exclusions apply for willful misconduct or gross negligence.

[[PAGE 6]]
6. TERM AND EXPIRATION
6.1 There is no auto-renewal. The contract simply ends at term end unless the customer explicitly requests extension in writing.
6.2 Customer data is retained for 60 days following termination to facilitate complete migration and export.
"""
    },

    "sample_c_defense_sow": {
        "id": "sample_c_defense_sow",
        "name": "Defense Cyber Subcontractor SOW & Security NDA",
        "description": "Government defense tier subcontracting agreement with strict data handling, zero-day disclosure mandates, and classified clearance compliance.",
        "text": """[[PAGE 1]]
DEFENSE SECURITY & INTELLIGENCE SUBCONTRACT (TIER 1)
Clearance Level: RESTRICTED // Ref: MOD-CYBER-2026-904

1. STATEMENT OF WORK AND SCOPE
1.1 Subcontractor shall provide autonomous cyber defense sensor maintenance and endpoint forensic capabilities.
1.2 Total contract ceiling value is Rs. 4,500,000 across a 24-month performance period.
1.3 Monthly retainer is fixed at Rs. 187,500/month. No setup or mobilization fees shall be permitted.

[[PAGE 2]]
2. CLASSIFIED DATA PROTECTION & EXPORT CONTROL
2.1 All data ingested, processed, or generated under this SOW is classified as Sovereign Strategic Information.
2.2 Data residency is restricted exclusively to Sovereign Domestic Data Centers located in India.
2.3 Any unauthorized transmission or external telemetry export constitutes a breach of national security and results in immediate contract revocation.

[[PAGE 3]]
3. MANDATORY VULNERABILITY DISCLOSURE & AUDIT
3.1 Subcontractor must disclose any discovered zero-day vulnerabilities or security anomalies within 4 hours of detection.
3.2 Ministry forensic audit teams retain perpetual rights to inspect subcontractor development environments without prior notice.

[[PAGE 4]]
4. TERMINATION FOR CAUSE & LIABILITIES
4.1 Government authority reserves the right to terminate immediately for national defense expediency.
4.2 Liability for security compromises, credential exposure, or data leakage is uncapped and subject to statutory prosecution.
4.3 Subcontractor must provide mandatory 90-day operational handover assistance upon termination at no additional charge.
"""
    }
}
