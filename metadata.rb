name             "hipsnip-jetty"
maintainer       "HipSnip Limited"
maintainer_email "adam@hipsnip.com/remy@hipsnip.com"
license          "Apache 2.0"
description      "Installs/Configures Jetty"
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          "0.8.2"
supports 'ubuntu', ">= 12.04"

depends "java"
depends "openssl"
depends "iptables", ">= 0.12.2"
