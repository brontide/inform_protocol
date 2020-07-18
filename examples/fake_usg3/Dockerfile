
FROM python:3

WORKDIR /app
COPY requirements.txt fake_usg3.py /app/
RUN apt update \
 && apt -y install build-essential libsnappy-dev\
 && pip install -r /app/requirements.txt \
 && chmod 755 fake_usg3.py

VOLUME [ "/app/data" ]

CMD ["python3", "-u", "/app/fake_usg3.py"]
