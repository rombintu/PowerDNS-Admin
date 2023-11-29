init:
	FLASK_APP=powerdnsadmin flask db upgrade
	yarn install
run:
	python3 run.py

babel-extract:
	pybabel extract -F babel.cfg -o messages.pot .

babel-update:
	pybabel update -i messages.pot -d powerdnsadmin/translations --locale ru

babel-compile:
	pybabel compile -d powerdnsadmin/translations --locale ru