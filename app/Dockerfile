FROM python:3.7

LABEL MAINTAINER="Graham Sheppard gsheppard@paloaltonetworks.com"

ENV APP_ENV="prod"
ENV APP_DEBUG="True"
ENV APP_PORT=5000
ENV MONGODB_DATABASE=flaskdb
ENV MONGODB_USERNAME=flaskuser
ENV MONGODB_PASSWORD=PrismaSDWAN
ENV MONGODB_HOSTNAME=mongodb
ENV SUPPORT_EMAIL="test@paloaltonetworks.com"
ENV ADMIN_USERNAME="admin"
ENV ADMIN_PASSWORD="PrismaSDWAN"
ENV PYTHONUNBUFFERED=1


WORKDIR /var/www/

ADD . /var/www/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install gunicorn

EXPOSE 5000
EXPOSE 5001

CMD [ "gunicorn", "-w", "1", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "--bind", "0.0.0.0:5000", "app:app", "--reload"]