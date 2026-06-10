# chmod 777 makes the directory world-writable — any process in the container
# can overwrite its contents.
# EXPECT: Medium DOCKERFILE-WORLD-WRITABLE
FROM ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN mkdir -p /data && chmod -R 777 /data
USER 10001
COPY app /app
