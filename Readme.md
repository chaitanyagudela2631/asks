# SOC Triage Agent with Hindsight Memory

A tier-1 security-alert triage agent that **learns from analyst decisions** using
[Hindsight](https://hindsight.vectorize.io/). The same alert types repeat every round, and several
malicious alerts share a rule name with benign ones (e.g. "Internal port scan detected"), so the agent
can only get better by remembering *specifics*.

| Operation | Where it's used |
|-----------|-----------------|
| `retain`  | After each alert, the analyst's verdict and reason are stored |
| `recall`  | Before each decision, similar past cases are fetched and shown to the LLM |
| `reflect` | At the end, the bank summarizes which patterns are benign vs. threats |

Expected result: round 1 is identical for both agents (empty memory). From round 2, the memory agent
stops escalating known-benign patterns (false alarms drop) while still escalating the real threats.

## Run it
1. Start Hindsight (it needs its own LLM key for fact extraction):
   ```bash
   pip install hindsight-api
   export HINDSIGHT_API_LLM_PROVIDER=groq
   export HINDSIGHT_API_LLM_API_KEY=<your Groq key>
   hindsight-api            # http://localhost:8888
   ```
   Or use Hindsight Cloud: set `HINDSIGHT_URL` and `HINDSIGHT_API_KEY` from the dashboard.
2. Run the demo:
   ```bash
   pip install -r requirements.txt
   export GROQ_API_KEY=<your Groq key>
   python soc_demo.py --rounds 3
   ```
Optional env vars: `LLM_MODEL` (default `openai/gpt-oss-120b`), `LLM_BASE_URL`, `SETTLE_SECONDS`
(pause after each retain so extraction finishes before the next recall; raise it if recall misses new memories).

`python soc_demo.py --offline` runs a simulated memory/LLM with no server or keys. It only checks the
harness; it is **not** Hindsight, so don't use its output in your demo.

## Next steps for the hackathon
Add a tiny UI (Streamlit) showing the accuracy chart, swap the synthetic alerts for real-looking logs, and
set a bank mission/disposition in Hindsight. Record the demo as: round 1 generic, round 3 personalized.