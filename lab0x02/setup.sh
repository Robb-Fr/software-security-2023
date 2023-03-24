#/bin/bash

python3 -m venv ~/Desktop/venv && source ~/Desktop/venv/bin/activate
echo "source ~/Desktop/venv/bin/activate" >> ~/.bashrc
pip install pwntools

bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

setxkbmap ch
