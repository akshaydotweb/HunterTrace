#!/usr/bin/env python3
"""Setup script for HUNTЕРТRACE."""

from setuptools import setup, find_packages
from pathlib import Path

# Read version
version = {}
version_file = Path(__file__).parent / "huntertrace" / "__version__.py"
if version_file.exists():
    with open(version_file) as f:
        exec(f.read(), version)
else:
    version = {
        '__title__': 'huntertrace',
        '__version__': '1.0.0',
        '__author__': 'HUNTЕРТRACE Contributors',
        '__author_email__': 'contact@huntertrace.io',
        '__description__': 'Advanced phishing actor attribution using Bayesian inference and graph analysis',
        '__url__': 'https://github.com/yourusername/huntertrace',
    }

# Read long description from README
this_directory = Path(__file__).parent
readme_file = this_directory / "README.md"
if readme_file.exists():
    long_description = readme_file.read_text(encoding='utf-8')
else:
    long_description = version['__description__']

setup(
    name=version['__title__'],
    version=version['__version__'],
    author=version['__author__'],
    author_email=version['__author_email__'],
    description=version['__description__'],
    long_description=long_description,
    long_description_content_type='text/markdown',
    url=version['__url__'],
    project_urls={
        'Documentation': 'https://github.com/yourusername/huntertrace/blob/main/docs',
        'Source': 'https://github.com/yourusername/huntertrace',
        'Tracker': 'https://github.com/yourusername/huntertrace/issues',
        'Changelog': 'https://github.com/yourusername/huntertrace/blob/main/CHANGELOG.md',
    },
    packages=find_packages(exclude=['tests', 'tests.*', 'examples', 'docs']),
    classifiers=[
        # Development status
        'Development Status :: 4 - Beta',
        
        # Intended audience
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        
        # Topic
        'Topic :: Security',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Communications :: Email',
        'Topic :: Internet :: Log Analysis',
        
        # License
        'License :: OSI Approved :: MIT License',
        
        # Python versions
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        
        # Other
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Environment :: Console',
    ],
    keywords=[
        'phishing',
        'attribution',
        'cybersecurity',
        'forensics',
        'email-analysis',
        'threat-intelligence',
        'bayesian-inference',
        'graph-analysis',
        'vpn-detection',
        'geolocation',
    ],
    python_requires='>=3.8',
    install_requires=[
        'networkx>=2.6',
        'numpy>=1.20.0',
        'requests>=2.25.0',
    ],
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.12',
            'black>=21.0',
            'flake8>=3.9',
            'mypy>=0.900',
            'build>=0.7',
            'twine>=3.4',
        ],
        'graph': [
            'python-louvain>=0.15',
        ],
        'whois': [
            'python-whois>=0.7.3',
        ],
        'all': [
            'python-louvain>=0.15',
            'python-whois>=0.7.3',
            'matplotlib>=3.3.0',
            'tqdm>=4.60.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'huntertrace=huntertrace.cli:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    platforms=['any'],
)
