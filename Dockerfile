FROM python:3.10.6

WORKDIR /app

ENV UV_SYSTEM_PYTHON=1
ENV PYTHONPATH=$PWD

RUN pip install uv

COPY pyproject.toml uv.lock /app/

RUN uv sync

COPY . /app

EXPOSE 8000

CMD ["sleep", "infinity"]