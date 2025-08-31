from setuptools import setup, find_packages

setup(
    name="IPDefender",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A project for blocking IPs using Cloudflare and integrating with threat intelligence feeds.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "requests",
        "PyYAML",
        "Flask",  # Assuming Flask is used for the web component
        "SQLAlchemy",  # Assuming SQLAlchemy is used for database interactions
        # Add other dependencies as needed
    ],
    extras_require={
        "dev": [
            "pytest",
            "flake8",
            # Add other development dependencies as needed
        ],
    },
    entry_points={
        "console_scripts": [
            "ipdefender=main:main",  # Adjust based on your main function location
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)