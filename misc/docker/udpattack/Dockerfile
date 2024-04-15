FROM docker.io/library/ubuntu:22.04

WORKDIR /app

RUN apt update && apt install -y tshark nginx tcpdump 

ADD ./payload.sh /app/payload.sh

RUN chmod +x payload.sh

ENTRYPOINT ["nginx", "-g", "daemon off;"]

