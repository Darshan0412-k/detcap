from setuptools import setup, find_packages

setup(
    name="detcap",
    version="1.0.0",
    author="Darshan G",
    description="AI-Powered Network Reconnaissance Tool",
    packages=find_packages(),
    install_requires=[
        "rich",
        "scapy"
    ],
    entry_points={
        "console_scripts": [
            "detcap=detcap.detcap:main"
        ]
    },
    python_requires=">=3.10",
)