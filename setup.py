from distutils.core import setup

setup(
    name='PyPTables',
    version='1.0.1',
    author='Jamie Cockburn',
    author_email='jamie_cockburn@hotmail.co.uk',
    packages=['pyptables',
              'pyptables.test',
              'pyptables.rules',
              'pyptables.rules.input',
              'pyptables.rules.forwarding',
              ],
    scripts=[],
    url='http://pypi.python.org/pypi/PyPTables/',
    license='LICENSE.txt',
    description='Python package for generating Linux iptables configurations.',
    long_description=open('README.rst').read(),
    install_requires=[
        "nose",
        "coverage",
    ],
)
