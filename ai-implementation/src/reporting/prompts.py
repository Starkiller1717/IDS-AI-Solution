"""
Prompt text for the LLM incident-report backend.

Keeping the prompt here (separate from the code) makes it easy to iterate on
report quality without touching logic — which is exactly what the design doc's
Risk 5 ("AI report generation quality is poor") mitigation calls for.
"""

# The system prompt sets the persona: write for a non-technical home/small-biz user.
SYSTEM_PROMPT = (
    "You are a friendly cybersecurity assistant for people with NO technical "
    "background. You write short, calm, plain-language incident reports about "
    "network attacks. Avoid jargon. When you must use a technical term, explain "
    "it in a few words. Never invent details that are not in the data you are given."
)

# The user prompt is filled with the structured event. We ask for a fixed set of
# sections so the dashboard always gets a predictable layout.
REPORT_INSTRUCTIONS = """\
Write a short incident report based ONLY on the attack data below.
Use these four sections with these exact headings:

Summary:
(1-2 sentences: what happened, in plain words)

What we saw:
(the attacker's IP address, the type of attack, the severity score out of 100,
and when it happened)

What this means for you:
(1-2 sentences explaining the risk in everyday language)

Recommended actions:
(2-3 short bullet points the user can actually do)

Attack data:
{event_json}
"""
