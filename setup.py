from setuptools import setup
setup(
    name='kent-boto-aws',    # This is the name of your PyPI-package.
    version='0.1',  
    py_modules=['botoawsplugin'],                     # Update the version number for new releases
    #scripts=['botoawsplugin']                 
    entry_points={
        'console_scripts': [
            'kent-boto-aws=botoawsplugin'
        ]
    }
)