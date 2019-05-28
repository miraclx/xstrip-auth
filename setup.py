import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="xstrip_auth",
    version="0.2.0",
    author="Miraculous Owonubi",
    author_email="omiraculous@gmail.com",
    description="Cryptographically strong pseudorandom key generator based on the XStrip Algorithm",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='Apache-2.0',
    url="https://github.com/miraclx/xstrip_auth",
    packages=['xstrip_auth'],
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
)
