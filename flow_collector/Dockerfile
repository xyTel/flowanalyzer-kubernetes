FROM ubuntu:latest

COPY . /root/data
RUN apt-get update && apt-get install -y python-pip && pip install -r /root/data/requirements.txt
ENTRYPOINT ["/root/data/init.sh"]
