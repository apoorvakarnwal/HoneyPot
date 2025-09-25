#1 create .env file. exmaple : HP_HTTP_PORT=8080 HP_SSH_PORT=2222

#2 setup .env

python3 -m venv .venv source .venv/bin/activate

#3 install requirements

pip install -r requirements.txt

docker setup #4 build the yml file

docker compose build

#5 up file

docker compose up

#check if running and then attack using attacker_sim

python attacker_sim/simulate.py --target 127.0.0.1

analyse logs - sample
python3 -m honeypot.services.analyzer --limit 100 | cat