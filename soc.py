#!/usr/bin/env python3
import os
"""SOC Alert Triage Agent that learns with Hindsight memory.

Every round, the same 8 kinds of alerts arrive (4 benign for THIS environment, 4 real threats,
several sharing the same rule name). Two agents triage them:
  * baseline : LLM only (no memory)              -> escalates anything suspicious-looking
  * memory   : LLM + Hindsight recall/retain     -> learns what analysts closed as benign
After each alert the analyst's decision is retained in Hindsight. Watch false alarms drop.

Run:  python soc_demo.py            (real Hindsight + Groq LLM)
      python soc_demo.py --offline  (no server/keys: simulated memory, harness smoke test only)
"""
import argparse, json, os, random, re, time

#  synthetic alert data
def p_backup(r):  return dict(rule="Internal port scan detected", host=f"bkp-srv-{r.randint(1,9):02d}", user="svc-backup", src=f"10.20.1.{r.randint(10,40)}", time=f"02:{r.randint(0,30):02d}", detail="Sequential SMB/445 connections to 60 file servers")
def p_qualys(r):  return dict(rule="Internal port scan detected", host="scan-01", user="svc-qualys", src="10.20.5.15", time=f"{r.randint(9,16)}:{r.randint(0,59):02d}", detail="Full TCP sweep of server VLAN from Qualys scanner")
def p_vpn(r):     return dict(rule="Impossible travel login", host="o365", user=f"sales{r.randint(1,30):02d}", src=f"vpn-exit-{r.choice(['sg','de','br'])}.corp.example", time=f"{r.randint(8,18)}:{r.randint(0,59):02d}", detail="Two logins 9 minutes apart from different countries, both via corporate VPN egress")
def p_sccm(r):    return dict(rule="Encoded PowerShell execution", host=f"it-ws-{r.randint(1,12):02d}", user="svc-sccm", src="10.20.8.4", time=f"03:{r.randint(0,59):02d}", detail="powershell -enc launched by CcmExec.exe during monthly patch window")
def p_laptop(r):  return dict(rule="Internal port scan detected", host=f"eng-lt-{r.randint(20,60)}", user="jdoe", src=f"10.30.{r.randint(1,9)}.{r.randint(20,200)}", time=f"{r.randint(13,17)}:{r.randint(0,59):02d}", detail="Connections to SSH/22 and RDP/3389 across server VLAN from a developer laptop")
def p_ato(r):     return dict(rule="Impossible travel login", host="o365", user=f"fin{r.randint(1,8):02d}", src=f"{r.randint(45,185)}.{r.randint(1,250)}.{r.randint(1,250)}.9", time=f"{r.randint(0,5):02d}:{r.randint(0,59):02d}", detail="Login from Lagos 12 minutes after Chicago login, no VPN, then a new inbox rule forwarding to an external address")
def p_macro(r):   return dict(rule="Encoded PowerShell execution", host=f"mkt-lt-{r.randint(1,40)}", user=f"mkt{r.randint(1,9):02d}", src=f"10.40.2.{r.randint(10,90)}", time=f"{r.randint(9,17)}:{r.randint(0,59):02d}", detail="powershell -enc spawned by WINWORD.EXE after opening an emailed .docm, then beaconing to a new domain")
def p_exfil(r):   return dict(rule="Large outbound transfer", host=f"eng-db-{r.randint(1,4):02d}", user="dbadmin", src=f"10.20.9.{r.randint(10,50)}", time=f"03:{r.randint(0,59):02d}", detail=f"{r.randint(20,60)} GB uploaded to an unknown personal cloud storage domain")

# (is_benign, analyst reason, generator)
PATTERNS = [
    (True,  "Approved nightly backup job (CHG-2291); expected scanning behavior", p_backup),
    (True,  "Authorized weekly Qualys vulnerability scan from 10.20.5.15", p_qualys),
    (True,  "Sales staff exit through corporate VPN nodes abroad; geo mismatch is expected", p_vpn),
    (True,  "SCCM monthly patch job uses encoded PowerShell on IT workstations", p_sccm),
    (False, "Developer laptop scanning server VLAN; confirmed unauthorized recon", p_laptop),
    (False, "Account takeover: finance user, no VPN, followed by mailbox forwarding rule", p_ato),
    (False, "Malicious macro dropper; host isolated", p_macro),
    (False, "Data exfiltration to personal cloud at 3am; incident opened", p_exfil),
]

def make_round(rng):
    alerts = [dict(g(rng), benign=b, reason=why) for b, why, g in PATTERNS]
    rng.shuffle(alerts)
    return alerts

def alert_text(a):
    return f"{a['rule']} | host {a['host']} | user {a['user']} | source {a['src']} | time {a['time']} | {a['detail']}"

def feedback_text(a):
    verdict = "BENIGN (closed)" if a["benign"] else "MALICIOUS (escalated)"
    return (f"SOC alert '{a['rule']}' on host {a['host']}, user {a['user']}, source {a['src']} at {a['time']}. "
            f"Behavior: {a['detail']}. Analyst verdict: {verdict}. Reason: {a['reason']}.")

#  LLM (Groq, OpenAI-compatible)
SYSTEM = ("You are a tier-1 SOC triage agent. For each alert answer ESCALATE (possible real threat) or CLOSE (benign). "
          "If unsure, ESCALATE. Past analyst decisions from memory may be listed; use one only if it matches this "
          "alert's user, source and behavior, otherwise judge the alert on its own. "
          'Reply with JSON only: {"verdict": "ESCALATE" or "CLOSE", "reason": "<one sentence>"}')

def parse_verdict(text):
    m = re.search(r'"?verdict"?\s*[:=]\s*"?(ESCALATE|CLOSE)', text or "", re.I)
    return m.group(1).upper() if m else "ESCALATE"      # safe default on malformed output

class LLM:
    def __init__(self):
        from openai import OpenAI
        self.client = OpenAI(base_url=os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"),
                             api_key=os.environ["GROQ_API_KEY"])
        self.model = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")

    def decide(self, text, memories):
        ctx = "\n".join(f"- {m}" for m in memories) or "(none)"
        msg = f"Alert: {text}\n\nPast analyst decisions from memory:\n{ctx}"
        for attempt in range(3):                          # retry on transient / tool-format errors
            try:
                r = self.client.chat.completions.create(model=self.model, temperature=0,
                    messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": msg}])
                return parse_verdict(r.choices[0].message.content)
            except Exception as e:
                print(f"  [llm retry {attempt+1}] {type(e).__name__}: {e}")
                time.sleep(1.5)
        return "ESCALATE"

#  memory backends
class HindsightMemory:
    """Thin wrapper over the Hindsight Python client: retain / recall / reflect."""
    def __init__(self, bank_id):
        from hindsight_client import Hindsight
        kw = {"base_url": os.getenv("HINDSIGHT_URL", "http://localhost:8888")}
        if os.getenv("HINDSIGHT_API_KEY"):
            kw["api_key"] = os.environ["HINDSIGHT_API_KEY"]
        self.client, self.bank = Hindsight(**kw), bank_id
        self.settle = float(os.getenv("SETTLE_SECONDS", "1"))

    def retain(self, text):
        self.client.retain(bank_id=self.bank, content=text)
        time.sleep(self.settle)                           # let fact extraction land before next recall

    def recall(self, query, k=5):
        res = self.client.recall(bank_id=self.bank, query=query)
        return [r.text for r in res.results][:k]

    def reflect(self, question):
        return self.client.reflect(bank_id=self.bank, query=question).text

TOK = lambda s: {t for t in re.findall(r"[a-z0-9./_-]+", s.lower()) if len(t) > 3}

class FakeMemory:
    """OFFLINE SIMULATION ONLY: keyword-overlap store. Not Hindsight."""
    def __init__(self): self.items = []
    def retain(self, text): self.items.append(text)
    def recall(self, query, k=5):
        q = TOK(query)
        scored = sorted(self.items, key=lambda m: -len(q & TOK(m)) / len(q | TOK(m)))
        return scored[:k]
    def reflect(self, question):
        return "(offline) " + str(len(self.items)) + " analyst decisions stored; reflect needs real Hindsight."

class RuleLLM:
    """OFFLINE SIMULATION ONLY: closes an alert if its closest remembered case was BENIGN."""
    def decide(self, text, memories):
        if memories:
            q, m = TOK(text), memories[0]
            if len(q & TOK(m)) / len(q | TOK(m)) >= 0.35 and "BENIGN" in m:
                return "CLOSE"
        return "ESCALATE"

#  demo loop
def score(alerts, verdicts):
    fp = sum(a["benign"] and v == "ESCALATE" for a, v in zip(alerts, verdicts))
    miss = sum((not a["benign"]) and v == "CLOSE" for a, v in zip(alerts, verdicts))
    return dict(accuracy=round(100 * (len(alerts) - fp - miss) / len(alerts)), false_alarms=fp, missed_threats=miss)

def bar(pct): return "█" * (pct // 10) + "░" * (10 - pct // 10)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--offline", action="store_true", help="simulate memory + LLM (no server, no keys)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if args.offline:
        print("*** OFFLINE SIMULATION: not using Hindsight or an LLM ***")
        llm, mem = RuleLLM(), FakeMemory()
    else:
        llm, mem = LLM(), HindsightMemory(f"soc-triage-{int(time.time())}")

    results = []
    for rnd in range(1, args.rounds + 1):
        alerts = make_round(rng)
        base, withmem = [], []
        for a in alerts:
            text = alert_text(a)
            base.append(llm.decide(text, []))                     # no memory
            withmem.append(llm.decide(text, mem.recall(text)))    # Hindsight recall
            mem.retain(feedback_text(a))                          # analyst decision -> Hindsight retain
        b, m = score(alerts, base), score(alerts, withmem)
        results.append(dict(round=rnd, baseline=b, memory=m))
        print(f"\nRound {rnd}: baseline false alarms {b['false_alarms']}, missed {b['missed_threats']} | "
              f"memory false alarms {m['false_alarms']}, missed {m['missed_threats']}")

    print("\nRound   Accuracy: no memory        Accuracy: with memory")
    for r in results:
        print(f"{r['round']:>3}     {bar(r['baseline']['accuracy'])} {r['baseline']['accuracy']:>3}%        "
              f"{bar(r['memory']['accuracy'])} {r['memory']['accuracy']:>3}%")

    print("\nWhat the agent learned (Hindsight reflect):")
    print(mem.reflect("Which alert patterns are normal and benign in this environment, and which look like real threats?"))
    with open("results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()