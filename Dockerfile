## Build stage 0 as base
#from lambci/lambda:build-python3.8 as build
##RUN mkdir /var/task
#WORKDIR /var/task
#
#COPY requirements.txt .
#RUN bash -c "pip install -r requirements.txt -t /var/task/; exit"
#
#FROM lambci/lambda:python3.8 as deploy
#COPY --from=build /var/task /var/task
#
#ENV DOCKER_LAMBDA_STAY_OPEN=1 \
#    DOCKER_LAMBDA_API_PORT=9001 \
#    AWS_LAMBDA_FUNCTION_NAME=lambda_function \
#    AWS_LAMBDA_FUNCTION_HANDLER=lambda_handler
#COPY lambda_function.py /var/task/
#VOLUME /var/task
#EXPOSE 9001
#FROM tiangolo/uvicorn-gunicorn-fastapi:python3.9


#
#COPY ./requirements.txt /app/requirements.txt
#
#RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt
#
#COPY ./app /app
#EXPOSE 8000
#CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
FROM python:3.9

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends \
libodbc2

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
