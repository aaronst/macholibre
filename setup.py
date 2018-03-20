import os
import sys

from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
NEWS = open(os.path.join(here, 'NEWS.txt')).read()


version = '1.0'


install_requires = [
    # List your project dependencies here.
    # For more details, see:
    # http://packages.python.org/distribute/setuptools.html#declaring-dependencies
    'asn1crypto'
]


setup(name='macholibre', version=version,
      description="Mach-O & Universal Binary Parser",
      long_description=README + '\n\n' + NEWS, classifiers=[],
      keywords='mach-o universal binary parser mac apple json',
      author='Aaron Stephens', author_email='aaronjst93@gmail.com', url='',
      license='Apache License 2.0', packages=find_packages('src'),
      package_dir={'': 'src'}, include_package_data=True, zip_safe=False,
      install_requires=install_requires, entry_points={
        'console_scripts': ['macholibre=macholibre:main']})
