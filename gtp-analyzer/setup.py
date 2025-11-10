from setuptools import setup, find_packages

setup(
    name='gtp-analyzer',
    version='1.0.0',
    description='Comprehensive GTP Wireshark PCAP analysis utility',
    author='Microservice Design Patterns',
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'click>=8.0.0',
        'tabulate>=0.9.0',
        'colorama>=0.4.6',
    ],
    entry_points={
        'console_scripts': [
            'gtp-analyzer=gtp_analyzer.cli:main',
        ],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: System :: Networking',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)
