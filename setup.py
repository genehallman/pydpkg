from setuptools import setup

__version__ = 0.1

setup(
    name='pydpkg',
    version=__version__,
    description="Evolution of dpkg-scanpackages -I",
    keywords='dpkg, deb',
    author='Greg Perkins',
    author_email='greg@livefyre.com',
    url='https://github.com/gregrperkins/pydpkg',
    license='BSD',
    scripts=['dpkg.py']
)
