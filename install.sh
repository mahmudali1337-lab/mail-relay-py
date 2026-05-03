#!/bin/bash
set -e

DIR=/opt/mail-relay-py
VENV=$DIR/venv

mkdir -p $DIR
cd $DIR

curl -fsSL https://raw.githubusercontent.com/mahmudali1337-lab/mail-relay-py/master/main.py -o main.py
curl -fsSL https://raw.githubusercontent.com/mahmudali1337-lab/mail-relay-py/master/requirements.txt -o requirements.txt

python3 -m venv $VENV
$VENV/bin/pip install --upgrade pip
$VENV/bin/pip install -r requirements.txt

cat > /etc/systemd/system/mail-relay-py.service << EOF
[Unit]
Description=Mail Relay Python
After=network.target

[Service]
WorkingDirectory=$DIR
ExecStart=$VENV/bin/python $DIR/main.py $DIR/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mail-relay-py
echo "Done. Copy config.yaml to $DIR/config.yaml then: systemctl start mail-relay-py"
