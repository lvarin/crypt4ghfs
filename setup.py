from setuptools import setup, find_packages

setup(name='crypt4ghfs',
      version='1.0',
      url='https://github.com/EGA-archive/crypt4ghfs',
      license='Apache License 2.0',
      author='EGA System Developers',
      description='Crypt4GH FUSE file system',
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
      install_requires=[
          'pyfuse3',
          'trio',
          'PyYaml',
          'crypt4gh>=1.4',
      ])
