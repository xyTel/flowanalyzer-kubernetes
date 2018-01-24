FROM ubuntu:latest

COPY . /root/data
RUN apt-get update && apt-get install -y python-pip && pip install -r /root/data/requirements.txt
CMD ["/root/data/init.sh", "elasticsearch.default.svc.cluster.local", "python", "/root/data/netflow_v9.py"]
