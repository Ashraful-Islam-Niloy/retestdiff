from setuptools import find_packages, setup

setup(
    name="retestdiff",
    version="0.1.0",
    description="Show what a pentest retest fixed, what is still open, and what came back",
    author="Ashraful Islam Niloy",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=("tests",)),
    entry_points={"console_scripts": ["retestdiff=retestdiff.cli:main"]},
)
