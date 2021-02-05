FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3
COPY entrypoint.sh /entrypoint.sh
COPY filter-sarif *.py /
ENTRYPOINT ["/entrypoint.sh"]
