FROM python:3.9-slim

RUN apt-get update &&     apt-get install -y git &&     git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap &&     apt-get remove -y git &&     apt-get autoremove -y &&     apt-get clean &&     rm -rf /var/lib/apt/lists/*

WORKDIR /sqlmap

EXPOSE 8775

CMD ["python3", "-m", "sqlmapapi", "-s", "-H", "0.0.0.0"]
