PY ?= python

setup:
	$(PY) -m pip install pydantic pyyaml pytest pypdf rapidocr-onnxruntime openai anthropic

run:
	$(PY) code/cli.py run --input dataset/deletion_requests.csv --output output.csv

eval:
	$(PY) code/evaluation/run.py --config configs/default.yaml

test:
	$(PY) -m pytest code/tests -q

zip:
	$(PY) scripts/make_zip.py
