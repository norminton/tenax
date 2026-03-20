from setuptools import setup, find_packages

setup(
    name="tenax",
    version="0.1.0",
    description="Linux persistence triage and artifact collection tool",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "tenax=tenax.cli:main",
        ],
    },
    python_requires=">=3.10",
)