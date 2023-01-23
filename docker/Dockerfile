FROM rust:latest AS builder

RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev
RUN update-ca-certificates

ENV USER=honeyaml
ENV UID=10001

RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "${UID}" \
  "${USER}"

COPY . .
WORKDIR /ctx

RUN cargo build --target x86_64-unknown-linux-musl --release

FROM scratch

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /honeyaml

# Copy our build
COPY --from=builder /ctx/target/x86_64-unknown-linux-musl/release/honeyaml ./
COPY --from=builder /ctx/api.yml ./

# Use an unprivileged user.
USER honeyaml:honeyaml

VOLUME ["/honeyaml/logs"]
CMD ["/honeyaml/honeyaml", "-d", "/honeyaml/logs" ]