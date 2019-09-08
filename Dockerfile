FROM python:3.7-alpine
ADD src VERSION /dist/
WORKDIR /dist
RUN apk add --update build-base libffi-dev openssl-dev && pip install -r requirements.txt
