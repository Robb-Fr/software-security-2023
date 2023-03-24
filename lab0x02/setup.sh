#/bin/bash

python3 -m venv ~/Desktop/venv && source ~/Desktop/venv/bin/activate
# echo "source ~/Desktop/venv/bin/activate" >> ~/.bashrc
pip install pwntools

bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

chown -hR tdemont ./

chmod +x ~/tsclient/SoftSecShared/software-security-2023/lab0x02/ghidra_10.2.3_PUBLIC/ghidraRun
chmod +x ~/tsclient/SoftSecShared/software-security-2023/lab0x02/ghidra_10.2.3_PUBLIC/support/launch.sh

setxkbmap ch fr_mac
