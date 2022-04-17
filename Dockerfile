FROM ubuntu:18.04

RUN apt-get update -y
RUN apt-get install -y build-essential
RUN apt-get install -y wget git
RUN apt-get install -y curl
RUN apt-get install -y zip

RUN cd /tmp
RUN wget https://go.dev/dl/go1.18.linux-amd64.tar.gz
RUN tar -C /usr/lib -xzf go1.18.linux-amd64.tar.gz
RUN rm -rf go1.18.linux-amd64.tar.gz

ENV GOPATH /go-path
ENV PATH $PATH:/usr/local/go/bin:$GOPATH/bin:/usr/local/go/bin

ENV APP_HOME /securitycodescanner

ENV PATH=/usr/lib/go/bin:$PATH

WORKDIR $APP_HOME

ADD . $APP_HOME

RUN echo $PATH
RUN go mod download

COPY . /securitycodescanner

CMD ["/bin/bash"]