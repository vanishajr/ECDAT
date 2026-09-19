FROM debian:stable-slim
RUN apt-get update && apt-get install -y openssl
COPY app.sh /app.sh
CMD ["/app.sh"]
