# Download with TLS certificate verification disabled (curl -k) — the payload
# can be swapped by a man-in-the-middle.
# EXPECT: High DOCKERFILE-TLS-VERIFICATION-DISABLED
FROM ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
USER 10001
RUN curl -k -o /tmp/app https://example.com/app
