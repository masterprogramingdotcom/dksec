from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        name="omnisec",
        version="1.0.0",
        description="Unified 9-Stage Product Security Lifecycle Orchestrator & Audit Engine",
        author="Product Security Architecture Team",
        packages=find_packages(),
        python_requires=">=3.8",
        install_requires=[
            "pyyaml>=6.0",
            "requests>=2.28.0",
            "jinja2>=3.0.0",
        ],
        entry_points={
            "console_scripts": [
                "omnisec=omnisec.cli:main",
            ],
        },
        classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "Intended Audience :: Information Technology",
            "Topic :: Security",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
        ],
    )
