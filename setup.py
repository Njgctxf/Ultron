from setuptools import setup, find_packages

setup(
    name="ultron-security",
    version="2.0.0",
    description="Autonomous RASP, Semantic AST WAF, Virtual Patching & DevSecOps Platform",
    author="Ultron AI Cyber Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "flask>=3.0.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "ultron-soc=web.server:main",
            "ultron-ci=ultron.ci_scanner:main",
        ],
    },
)
