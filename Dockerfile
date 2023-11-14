FROM    python:3.12.0

WORKDIR /usr/src/clicker

RUN     apt update && apt install -y cargo

COPY    requirements.txt .
RUN     pip install -r requirements.txt

COPY    . .

RUN     --mount=type=secret,id=clicker_secret_key \
        echo "CLICKER_SECRET_KEY=$(cat /run/secrets/clicker_secret_key)" > /etc/environment \

CMD     ["python", "server.py"]
