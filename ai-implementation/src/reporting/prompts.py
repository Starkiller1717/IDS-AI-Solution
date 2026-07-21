"""
Prompt text for the LLM incident-report backend.

Keeping the prompt here (separate from the code) makes it easy to iterate on
report quality without touching logic — which is exactly what the design doc's
Risk 5 ("AI report generation quality is poor") mitigation calls for.
"""

# Mandatory, verbatim closing line -- see REPORT_INSTRUCTIONS below. Shared as a
# constant so report.py's code-level backstop can't drift from the prompt wording.
NO_AUTO_BLOCK_DISCLAIMER = "No automatic blocking or network lockdown was performed."

# The system prompt sets the persona: write for a non-technical home/small-biz user.
SYSTEM_PROMPT = (
    "You are a friendly cybersecurity assistant for people with NO technical "
    "background. You write short, calm, plain-language incident reports about "
    "network attacks. Avoid jargon. When you must use a technical term, explain "
    "it in a few words. Never invent details that are not in the data you are given. "
    "Output PLAIN TEXT only: no markdown, no **bold**, no # headings, no preamble "
    "or closing remarks before/after the report itself -- start directly with the "
    "first requested heading."
)

# The user prompt is filled with the structured event. We ask for a fixed set of
# sections so the dashboard always gets a predictable layout. The safety-wording
# line is mandatory, not a suggestion: this system never blocks traffic or locks
# down the network, and the report must never imply otherwise (see design doc
# Risk 5 mitigation / Documents/PROGRESS.md). _ollama_report() in report.py also
# enforces this line in code as a backstop, since LLM instruction-following isn't
# guaranteed.
REPORT_INSTRUCTIONS = f"""\
Write a short incident report based ONLY on the attack data below.
Use PLAIN TEXT with exactly these five sections, in this order, with these exact
plain headings (no markdown, no bold, no numbering, no extra sections, nothing
before "Summary:" or after the last bullet):

Summary:
(1-2 sentences: what happened, in plain words)

What we saw:
(the attacker's IP address, the type of attack, the severity score out of 100,
and when it happened)

What this means for you:
(1-2 sentences explaining the risk in everyday language)

Recommended actions:
(2-3 short bullet points the user can actually do, each starting with "- ")

Then end with this exact sentence, unchanged, as its own final line:
{NO_AUTO_BLOCK_DISCLAIMER}

Attack data:
{{event_json}}
"""
