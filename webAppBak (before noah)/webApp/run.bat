@echo off
cd ..
cd venv
call Scripts\activate
cd ..
cd webApp
set FLASK_APP=__init__.py
flask run
cmd