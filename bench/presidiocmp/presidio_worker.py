# The program under test for presidiocmp: Microsoft Presidio's analyzer,
# driven over stdin/stdout. One JSON object per line in: {"id", "text"};
# one per line out: {"id", "ns", "results": [{"type", "start", "end", "score"}]}
# where ns is the time spent in AnalyzerEngine.analyze alone (perf_counter_ns)
# and start/end are Python string indices (code points). All logic --
# scoring, offsets, statistics -- is in the Go harness.
import json
import sys
import time

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

model = sys.argv[1] if len(sys.argv) > 1 else "en_core_web_lg"
provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": model}],
})
analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD", "IP_ADDRESS"]

print(json.dumps({"ready": True}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    t0 = time.perf_counter_ns()
    found = analyzer.analyze(text=req["text"], language="en", entities=ENTITIES)
    ns = time.perf_counter_ns() - t0
    print(json.dumps({"id": req["id"], "ns": ns, "results": [
        {"type": r.entity_type, "start": r.start, "end": r.end, "score": r.score} for r in found
    ]}), flush=True)
