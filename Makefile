sdist:
	./setup.py sdist

upload:
	./setup.py sdist upload

clean:
	rm -rf AUTHORS ChangeLog dist yaycl_crypt.egg-info __pycache__ *.egg .coverage
