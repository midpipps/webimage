#Docker image for running wkhtmltoimage with the python scanner.
#TODO cut the image size down by being more selective about what is installed and base starting image since this image is about 700MB at this time
FROM ubuntu:14.04

LABEL  maintainer="Lucas Pippenger"

#set the working directory for our image
WORKDIR /usr/src/webimage

#get python3 and all other required libs
RUN apt-get update && apt-get install -y --no-install-recommends \
                                      python3 \
                                      python3-pip \
                                      wget \
                                      xz-utils \
                                      libssl-dev \
                                      build-essential \
                                      xorg \
                                      libxrender-dev \
                                      gdebi \
                   && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
                   && pip3 install pip --upgrade \
                   && mkdir output


#get the wkhtml
RUN wget "https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz" \
    && tar -xpvf "wkhtmltox-0.12.4_linux-generic-amd64.tar.xz" \
    && rm -f "wkhtmltox-0.12.4_linux-generic-amd64.tar.xz"

#copy the requirements and install them as needed
COPY requirements.txt ./
RUN ["pip3", "install", "-r", "requirements.txt"]

#copy the webimage python file into the docker so we can use it as our entry point
COPY webimage.py ./

#set the start script
ENTRYPOINT [ "/usr/bin/python3", "webimage.py" ]
