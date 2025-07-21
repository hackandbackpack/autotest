"""Setup script for AutoTest"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), encoding='utf-8') as f:
        return f.read()

# Get version
def get_version():
    with open(os.path.join(os.path.dirname(__file__), 'autotest.py'), 'r') as f:
        for line in f:
            if line.startswith('__version__'):
                return line.split('=')[1].strip().strip('"').strip("'")
    return '1.0.0'

setup(
    name='autotest-pentest',
    version=get_version(),
    description='Automated Network Penetration Testing Framework',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='Security Team',
    author_email='security@example.com',
    url='https://github.com/example/autotest',
    license='MIT',
    packages=find_packages(exclude=['tests*', 'docs*']),
    include_package_data=True,
    install_requires=[
        'aiofiles>=23.2.1',
        'asyncio>=3.4.3',
        'pyyaml>=6.0',
        'jinja2>=3.1.2',
        'python-nmap>=0.7.1',
        'requests>=2.31.0',
        'aiohttp>=3.9.0',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'lxml>=4.9.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-asyncio>=0.21.0',
            'pytest-cov>=4.1.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.5.0',
            'sphinx>=7.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'autotest=autotest:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
    ],
    python_requires='>=3.8',
    keywords='security penetration-testing automation network scanner vulnerability',
)