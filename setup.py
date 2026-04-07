from setuptools import setup, find_packages

setup(
    name="apisec",
    version="1.0",
    packages=find_packages(),
    py_modules=["main"],
    entry_points={
        "console_scripts": [
            "apisec=main:main",
        ],
    },
)