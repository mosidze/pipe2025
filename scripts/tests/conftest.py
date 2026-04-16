import sys
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture
def sample_workflow_yaml() -> str:
    return """on:
  push: {}
  workflow_dispatch: {}
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo ok
"""


@pytest.fixture
def sample_dockerfile_clean() -> str:
    return """FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . ./
RUN go build -o /out/login ./cmd/login

FROM alpine:3.20
# USER root
RUN echo ready
COPY --from=builder /out/login /login
USER 65532:65532
HEALTHCHECK CMD ["/bin/true"]
ENTRYPOINT ["/login"]
"""


@pytest.fixture
def sample_dockerfile_broken() -> str:
    return """FROM golang:rc-stretch
COPY ./ /src
WORKDIR /src
RUN go install github.com/coolbet/login/cmd/login
ENTRYPOINT login
"""
