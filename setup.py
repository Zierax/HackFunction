# setup.py

from setuptools import setup, find_packages


setup(
    name="hackfunc",
    version="1.0.0",
    description="A toolkit for basic security checks and scans",
    long_description="HackFunction is a versatile toolkit designed to facilitate basic security checks and scans for systems, networks, and web applications. Whether you are a security enthusiast, a network administrator, or a developer looking to enhance the security posture of your infrastructure, Hackit offers a suite of tools to assist you in identifying vulnerabilities and ensuring the robustness of your environment.",
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
    license='MIT',  
    url='https://github.com/Zierax/HackFunction',  
    project_urls={
        'Documentation': 'https://github.com/Zierax/HackFunction/docs',
        'Source': 'https://github.com/Zierax/HackFunction',
        'Tracker': 'https://github.com/Zierax/HackFunction/issues',
    },
)
