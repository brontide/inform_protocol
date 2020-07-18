from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='inform',
      version='0.1',
      description='Encode and decode unifi inform packets',
      long_description=readme(),
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
      ],
      keywords='UBNT unifi inform',
      url='http://github.com/brontide/inform',
      author='Eric Warnke',
      author_email='ericew@gmail.com',
      license='MIT',
      packages=['inform'],
      install_requires=[
          'Padding',
          'pysnappy',
          'pycryptodome',
          'requests',
      ],
#      entry_points={
#          'console_scripts': ['unificmd=unifiapi.cmd:main'],
#      },
      include_package_data=True,
      zip_safe=False)
