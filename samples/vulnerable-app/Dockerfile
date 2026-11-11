# DELIBERATELY VULNERABLE - test fixture for the VAPT scanner.
FROM python:latest
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENV DB_PASSWORD=Sup3rS3cretPassw0rd!
EXPOSE 22 5000
CMD python app.py
