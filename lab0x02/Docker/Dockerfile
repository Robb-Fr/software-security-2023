FROM --platform=amd64 ubuntu:20.04

RUN apt update && apt upgrade -y

# export timezone - for python3.9-dev install
ENV TZ=Europe/London

# place timezone data /etc/timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt install -y --no-install-recommends python3 python3-pip

RUN apt install -y build-essential gdb

RUN pip install --upgrade pip && pip install pwntools

RUN curl -fsSL https://gef.blah.cat/sh | sh

RUN apt install -y git && pip install r2env && r2env init && r2env add radare2@git

RUN apt install -y curl wget

RUN curl -fsSL https://raw.githubusercontent.com/cdr/code-server/main/install.sh | sh

WORKDIR /lab2

COPY ./ms-vscode.cpptools-1.14.5@linux-x64.vsix /lab2/ms-vscode.cpptools-1.14.5@linux-x64.vsix

RUN code-server --force --install-extension /lab2/ms-vscode.cpptools-1.14.5@linux-x64.vsix

ENTRYPOINT [ "bash" ]