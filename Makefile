RAWVERSION = $(filter-out __version__ = , $(shell grep __version__ m2m_cognito/__init__.py))
VERSION = $(strip $(shell echo $(RAWVERSION)))

PACKAGE = m2m-cognito

clean:
	rm -rf *.tar.gz dist build *.egg-info *.rpm
	find . -name "*.pyc" | xargs rm
	find . -name "__pycache__" | xargs rm -rf

version:
	@echo $(VERSION)

dist: clean
	@python -m build

release: dist
	@bin/release.sh

compile: uv.lock
	@uv pip compile --group test pyproject.toml -o requirements.txt
