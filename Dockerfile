FROM python:3.6-alpine
ADD src BASE-VERSION /dist/
WORKDIR /dist
RUN apk add --update build-base libffi-dev openssl-dev && pip install -r base-requirements.txt
