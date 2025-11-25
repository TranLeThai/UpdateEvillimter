import os
import re
import sys
import shutil
import glob
from setuptools import setup, find_packages, Command

# Đường dẫn gốc của dự án
HERE = os.path.abspath(os.path.dirname(__file__))

class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # Các thư mục và file cần xóa
        cleanup_targets = [
            './build',
            './dist',
            './*.egg-info',
            './__pycache__',
            './evillimiter/__pycache__',
            './evillimiter/*/__pycache__' # Subdirectories
        ]
        
        print("Cleaning project...")
        
        for pattern in cleanup_targets:
            # Tìm tất cả các path khớp pattern
            for path in glob.glob(pattern):
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                        print(f"Removed directory: {path}")
                    else:
                        os.remove(path)
                        print(f"Removed file: {path}")
                except Exception as e:
                    print(f"Error removing {path}: {e}")

def get_init_content():
    init_path = os.path.join(HERE, 'evillimiter', '__init__.py')
    if not os.path.exists(init_path):
        # Fallback nếu file chưa tồn tại (để tránh crash setup)
        return ""
        
    with open(init_path, 'r', encoding='utf-8') as f:
        return f.read()

def get_version():
    content = get_init_content()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", content, re.M)
    if version_match:
        return version_match.group(1)
    return "0.0.0" # Default version if not found

def get_description():
    content = get_init_content()
    desc_match = re.search(r"^__description__ = ['\"]([^'\"]*)['\"]", content, re.M)
    if desc_match:
        return desc_match.group(1)
    return "Network traffic limiter tool"

NAME = 'evillimiter'
AUTHOR = 'bitbrute'
AUTHOR_EMAIL = 'bitbrute@gmail.com'
LICENSE = 'MIT'
VERSION = get_version()
URL = 'https://github.com/bitbrute/evillimiter'
DESCRIPTION = get_description()

# Đọc README làm long description (nếu có)
try:
    with open(os.path.join(HERE, 'README.md'), 'r', encoding='utf-8') as f:
        LONG_DESCRIPTION = f.read()
except FileNotFoundError:
    LONG_DESCRIPTION = DESCRIPTION

KEYWORDS = ["evillimiter", "limit", "bandwidth", "network", "traffic-control", "arp-spoofing"]
PACKAGES = find_packages()
INCLUDE_PACKAGE_DATA = True

CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Intended Audience :: System Administrators',
    'Intended Audience :: End Users/Desktop',
    'License :: OSI Approved :: MIT License',
    'Natural Language :: English',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Topic :: System :: Networking',
    'Topic :: Security',
]

PYTHON_REQUIRES = '>=3.6'

# Entry point: Khi cài xong, gõ 'evillimiter' trong terminal sẽ chạy hàm run()
ENTRY_POINTS = {
    'console_scripts': [
        'evillimiter = evillimiter.evillimiter:run'
    ]
}

INSTALL_REQUIRES = [
    'colorama',
    'netaddr',
    'netifaces',
    'tqdm',
    'scapy',
    'terminaltables'
]

CMDCLASS = {
    'clean': CleanCommand
}

setup(
    name=NAME,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    license=LICENSE,
    keywords=KEYWORDS,
    packages=PACKAGES,
    include_package_data=INCLUDE_PACKAGE_DATA,
    version=VERSION,
    python_requires=PYTHON_REQUIRES,
    entry_points=ENTRY_POINTS,
    install_requires=INSTALL_REQUIRES,
    classifiers=CLASSIFIERS,
    url=URL,
    cmdclass=CMDCLASS,
)