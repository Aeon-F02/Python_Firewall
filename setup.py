from setuptools import setup, find_packages

setup(
    name='AeonF',  # Name of your package
    version='1.0.1',  # Version of your project
    author='Aeon_Flux',  # Author name (you can change this)
    author_email='Aeonflux330@gmail.com',  # Author email
    description='A Python-based firewall with packet sniffing, rule enforcement, and traffic monitoring.',
    long_description=open('docs/README.md').read(),  # Long description read from README
    long_description_content_type='text/markdown',
    url='https://github.com/Aeon-F02/Python_Firewall',  # Change to your repositry URL if hosted on GitHub or similar
    packages=find_packages(where='src'),  # Automatically find packages in src
    package_dir={'': 'src'},  # Specify that source code is in the `src` folder
    install_requires=[  # List of dependencies required to run your project
        'pyyaml',  # YAML handling
        'scapy',  # For packet sniffing
        'requests',  # If required for network interactions (e.g., monitoring)
        'psutil',  # For system-level traffic monitoring (optional, depending on your needs)
        'pytest',  # If you are running tests with pytest
    ],
    entry_points={  # To make your tool executable via CLI
        'console_scripts': [
            'Aeon-f = src.cli.manage_firewall:main',  # Adjust to your main entry point
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',  # You can change this based on your project's license
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Development Status :: 3 - Alpha',  # Or change the status to production when ready
    ],
    python_requires='>=3.6',  # Specify the minimum Python version required
    include_package_data=True,  # Ensure data files like configurations are included
    data_files=[  # Example: include any configuration files in the installation
        ('configs', ['src/configs/default_rules.json', 'src/configs/settings.yaml']),
    ],
    # Optional: if you have a package for testing
    test_suite='tests',  # Point to your tests folder
)
