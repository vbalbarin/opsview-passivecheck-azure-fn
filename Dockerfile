FROM mcr.microsoft.com/azure-functions/python:4-python3.12

COPY . /home/site/wwwroot

RUN cd /home/site/wwwroot && \
    pip install -r requirements.txt