####################################
# Copyright 2017 Ryan David Williams
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
####################################

FROM ubuntu:latest
LABEL maintainer="Ryan D Williams <rdw@drws-office.com>"

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install \
    python3 \
    python3-pip \
    apache2 \
    libapache2-mod-wsgi-py3 \
  && rm -rf /var/lib/apt/lists/*

ADD requirements.txt /
RUN pip3 install -r /requirements.txt

ADD conf /etc/password_interface

RUN ln -s /etc/password_interface/apache2.conf /etc/apache2/sites-available/password_interface.conf \
  && a2ensite password_interface \
  && a2dissite 000-default \
  && a2enmod wsgi

ADD src /opt/passwd_if

EXPOSE 80

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]