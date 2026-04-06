from setuptools import setup, find_packages

setup(
    name="arman",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "rich",
        "urllib3"
    ],
    entry_points={
        "console_scripts": [
            "arman=arman.main:start"
        ]
    },
    python_requires=">=3.8",
)