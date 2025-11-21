from setuptools import find_packages, setup

setup(
    name='pcap-alter',
    version='0.0.1',
    author='Koen Teuwen',
    python_requires='>=3.10',
    install_requires=(
        'scapy>=2.5.0',
        'numpy>=1.23.5',
    ),
    packages=find_packages(exclude='tests'),
)

