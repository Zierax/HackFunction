# setup.py

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hackfunc",
    version="1.0.0",
    description="A comprehensive toolkit for security analysis and blockchain interactions",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="Zierax",
    author_email="zs.01117875692@gmail.com",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "dnspython",
        "python-whois",
        "python-nmap",
        "scapy",
        "ping3",
        "web3",
        "eth-abi",
        "eth-utils",
        "solidity-parser",
        "networkx",
        "z3-solver",
        "python-dotenv",
        "slither-analyzer",
        "mythril",
        "manticore",
        "pyevmasm",
        "eth-bloom",
        "eth-account",
        "rlp",
        "tqdm",
        "scipy",
        "numpy",
        "scikit-learn",
        "cryptography",
        "aiohttp",
    ],
    extras_require={
        'testing': ['pytest'],
        'dev': ['black', 'flake8', 'mypy'],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    license='MIT',  
    url='https://github.com/Zierax/HackFunction',  
    project_urls={
        'Documentation': 'https://github.com/Zierax/HackFunction/docs',
        'Source': 'https://github.com/Zierax/HackFunction',
        'Tracker': 'https://github.com/Zierax/HackFunction/issues',
    },
    entry_points={
        'console_scripts': [
            'hackfunc=hackfunc.cli:main',
        ],
    },
)
