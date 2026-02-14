from setuptools import setup

setup(
    name="sandbox-cmd-analyzer",
    version="0.1.0",
    description="Sandbox command analyzer for C2 frameworks",
    author="Snoopy",
    py_modules=["sandbox_analyzer"],
    install_requires=[
        "docker>=7.0.0",
        "scapy>=2.5.0",
        "grpcio>=1.60.0",
        "protobuf>=4.25.0",
        "dnslib>=0.9.23",
        "click>=8.1.7",
        "cryptography>=42.0.0",
        "pyOpenSSL>=23.3.0",
        "pyelftools>=0.31",
        "cffi>=1.16.0",
        "pynacl>=1.5.0",
    ],
    entry_points={
        "console_scripts": [
            "sandbox-cmd-analyzer=sandbox_analyzer:main",
        ],
    },
    python_requires=">=3.8",
)
