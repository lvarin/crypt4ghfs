import sys
assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"

from pathlib import Path
from setuptools import setup, find_packages

_readme = (Path(__file__).parent / "README.md").read_text()

setup(name='crypt4ghfs',
      version='1.1',
      url='https://github.com/EGA-archive/crypt4ghfs',
      license='Apache License 2.0',
      author='Frédéric Haziza',
      author_email='frederic.haziza@crg.eu',
      description='Crypt4GH FUSE file system',
      long_description=_readme,
      long_description_content_type="text/markdown",
      packages=find_packages(),
      include_package_data=False,
      package_data={},
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'crypt4ghfs = crypt4ghfs.__main__:main',
          ]
      },
      platforms='any',
      classifiers=[  # Optional
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: Apache Software License',

          'Natural Language :: English',
          'Operating System :: POSIX',
          'Operating System :: POSIX :: Linux',

          'Intended Audience :: Developers',
          'Intended Audience :: Healthcare Industry',
          'Intended Audience :: Information Technology',
          'Topic :: Security :: Cryptography',
          'Topic :: System :: Filesystems',
          'Topic :: Scientific/Engineering :: Bio-Informatics',

          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',

          'Programming Language :: Python :: Implementation :: CPython',
      ],
      python_requires='>=3.6',
      # See https://packaging.python.org/discussions/install-requires-vs-requirements/
      install_requires=[
          'pyfuse3',
          'trio',
          'crypt4gh>=1.4',
      ],
)
