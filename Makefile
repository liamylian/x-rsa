test_go:
	cd golang && go test ./...

init_php:
	cd php && composer install
test_php:
	cd php && ./vendor/bin/phpunit  XRsaTest.php

init_python:
	( \
		cd python; \
		python3 -m venv venv; \
		. ./venv/bin/activate; \
		pip3 install -r requirements.txt; \
	)
test_python:
	( \
		cd python; \
		. ./venv/bin/activate; \
		python3 -m unittest xrsa_test.py; \
	)

init_java:
	cd java && mvn install
test_java:
	cd java && mvn test
