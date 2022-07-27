from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(name="gnukek-cli",
      version="0.1.0",
      author="SweetBubaleXXX",
      license="GNU General Public License v3.0",
      description="Kinetic Effective Key CLI",
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
          "gnukek==1.0.0b3",
      ],
      extras_require={
          "dev": [
              "mypy",
              "pycodestyle"
          ],
          "build": [
              "build",
              "twine"
          ]
      },
      python_requires=">=3.7",
      # test_suite="tests",
      entry_points={
          "console_scripts": ["kek=KEK_cli:main"]
      })
