PYTHON ?= python3
VENV ?= .venv
ACTIVATE = . $(VENV)/bin/activate

.PHONY: install install-kali test doctor dashboard deploy-http deploy-ssh clean

install:
	$(PYTHON) -m venv $(VENV)
	$(ACTIVATE) && pip install --upgrade pip
	$(ACTIVATE) && pip install -r requirements.txt

install-kali:
	bash scripts/bootstrap_kali.sh

test:
	$(ACTIVATE) && python -m unittest discover -s tests -v

doctor:
	$(ACTIVATE) && python main.py doctor

dashboard:
	$(ACTIVATE) && python main.py dashboard

deploy-http:
	$(ACTIVATE) && python main.py deploy http --port 8080

deploy-ssh:
	$(ACTIVATE) && python main.py deploy ssh --port 2222

clean:
	rm -rf $(VENV) __pycache__ dashboard/__pycache__ manager/__pycache__ manager/runtime/__pycache__ tests/__pycache__
