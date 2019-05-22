import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="xtrip_auth",
    version="0.1.0",
    author="Miraculous Owonubi",
    author_email="omiraculous@gmail.com",
    description="Cryptographically strong pseudorandom key generator based on the XStrip Algorithm",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='Apache-2.0',
    url="https://github.com/miraclx/xtrip_auth",
    packages=['xtrip_auth'],
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
)
