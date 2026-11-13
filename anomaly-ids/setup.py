from setuptools import find_packages, setup

setup(
    name="anomaly_detector",
    version="1.1.0",
    description="Prototype network anomaly detection: Windows logs + PCAP flows + Isolation Forest",
    author="Paul DeFrain",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests"]),
    package_data={"anomaly_detector": ["templates/*.html"]},
    install_requires=[
        "pandas>=1.5",
        "numpy>=1.23",
        "scikit-learn>=1.2",
        "click>=8.0",
        "jinja2>=3.0",
    ],
    extras_require={
        "live": ["scapy>=2.5"],
        "dashboard": ["streamlit>=1.30", "altair>=5.0"],
        "dev": ["pytest>=7.0"],
        "all": ["scapy>=2.5", "streamlit>=1.30", "altair>=5.0", "pytest>=7.0"],
    },
    entry_points={"console_scripts": ["anomaly-detect=anomaly_detector.cli:cli"]},
)
