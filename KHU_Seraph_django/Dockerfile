# Dockerfile
# Set base image 
FROM python:3.8
ENV PYTHONUNBUFFERED 1
# Set maintainer
MAINTAINER "Jaeho Lee <dlwogh9344@khu.ac.kr>"

RUN mkdir /srv/docker-server
ADD . /srv/docker-server

WORKDIR /srv/docker-server

# Install packages
RUN pip install --upgrade pip && pip install -r requirements.txt