Quickstart (plain text)

1) go to project directory
cd /Users/shiveshkaushik/Downloads/cyber-sec-honeypot

2) create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

3) install python dependencies
pip3 install -r requirements.txt

4) remove any previous honeypot container (ignore error if none exists)
docker rm -f honeypot_local || true

5) build and start honeypot
docker compose up -d --build

6) verify container is running
docker ps | grep honeypot_local

7) run attack simulation against local honeypot
python3 attacker_sim/simulate.py --target 127.0.0.1

8) analyze logs and generate charts
python3 analysis/comprehensive_attack_analysis.py logs/honeypot_events.jsonl
python3 analysis/advanced_threat_analysis.py logs/honeypot_events.jsonl
python3 analysis/generate_threat_report.py

9) view dashboard and charts
open analysis/security_dashboard.html
open analysis/charts

10) tail logs (optional)
tail -f logs/honeypot_events.jsonl

11) rebuild and restart quickly (optional one-liner)
docker rm -f honeypot_local || true && docker compose up -d --build

12) stop honeypot
docker compose down