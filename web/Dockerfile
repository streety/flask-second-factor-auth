FROM python:3.6

RUN apt-get update
RUN apt-get install -y build-essential libssl-dev libffi-dev python3-dev

#
# Installing python packages and bringing in code
#

RUN mkdir -p /app
WORKDIR /app
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt
