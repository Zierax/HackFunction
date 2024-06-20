# setup.py

from setuptools import setup, find_packages



setup(
    name="hackit",
    version="1.0.0",
    description="A toolkit for basic security checks and scans",
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
        "dns.resolver",
        "ping3",
    ],
    extras_require={
        'testing': ['pytest'],
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    license='MIT',  # Specify the license
    url='https://github.com/Zierax/hackit',  # Replace with your project URL
    project_urls={
        'Documentation': 'https://github.com/Zierax/hackit/docs',
        'Source': 'https://github.com/Zierax/hackit',
        'Tracker': 'https://github.com/Zierax/hackit/issues',
    },
)
