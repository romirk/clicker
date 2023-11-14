FROM    python:3.12.0

WORKDIR /usr/src/clicker

RUN     apt update && apt install -y cargo

COPY    requirements.txt .
RUN     pip install -r requirements.txt

COPY    . .

RUN     --mount=type=secret,id=clicker_secret_key \
        cat /run/secrets/clicker_secret_key > ./server.key

CMD     ["python", "server.py", "/usr/src/clicker/server.key"]
