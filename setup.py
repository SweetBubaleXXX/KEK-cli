from setuptools import find_packages, setup

from KEK_cli import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(name="gnukek-cli",
      version=__version__,
      author="SweetBubaleXXX",
      license="GNU General Public License v3.0",
      description="Kinetic Encryption Key CLI",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url="https://github.com/SweetBubaleXXX/KEK-cli",
      project_urls={
          "Source": "https://github.com/SweetBubaleXXX/KEK-cli",
          "Bug Tracker": "https://github.com/SweetBubaleXXX/KEK-cli/issues"
      },
      classifiers=[
          "Development Status :: 2 - Pre-Alpha",
          "Topic :: Security :: Cryptography",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Programming Language :: Python :: 3",
          "Operating System :: OS Independent",
      ],
      packages=find_packages(include=["KEK_cli*"]),
      install_requires=[
          "gnukek==1.0.0b6",
      ],
      extras_require={
          "dev": [
              "mypy",
              "pycodestyle",
              "pylint"
          ],
          "build": [
              "build",
              "twine"
          ]
      },
      python_requires=">=3.7",
      entry_points={
          "console_scripts": ["kek=KEK_cli.entry_point:main"]
      })
