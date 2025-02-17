from setuptools import setup, find_packages

setup(
    name="secure-vault",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography>=41.0.0',
        'click>=8.0.0',
        'flask>=2.0.0',
        'pydantic>=2.0.0',
        'structlog>=23.0.0',
        'python-dotenv>=1.0.0',
    ],
    entry_points={
        'console_scripts': [
            'secure-vault=secure_vault.cli:main',
        ],
    },
)