#/bin/bash

python3 -m venv ~/Desktop/venv && source ~/Desktop/venv/bin/activate
# echo "source ~/Desktop/venv/bin/activate" >> ~/.bashrc
pip install pwntools

bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

pip install r2env && r2env init && r2env add radare2@git

chown -hR tdemont ./

setxkbmap ch fr_mac
