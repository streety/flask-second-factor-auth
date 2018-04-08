FROM nginx:1.13.1
RUN rm /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/
RUN rm /etc/nginx/conf.d/default.conf
COPY sites/ /etc/nginx/conf.d/
RUN apt-get update
RUN apt-get install -y openssl
RUN mkdir /certs
RUN openssl req -x509 -newkey rsa:4096 -keyout /certs/key.pem -out /certs/cert.pem -days 365 -nodes -subj '/CN=u2f-demo.local'
