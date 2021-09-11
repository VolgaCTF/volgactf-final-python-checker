FROM python:3.7-slim
ADD src VERSION /dist/
WORKDIR /dist
RUN apt-get update && apt-get install -y build-essential libffi-dev libssl-dev && pip install --upgrade pip && pip install --requirement requirements.txt
