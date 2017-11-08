# webimage
Simple program for searching for http/s pages in a range of IP addresses. if it finds one it can grab an image of the rendered page using wkhtmltoimage and the html of the home

#usage
```
usage: webimage.py [-h] [--ports PORTS] [--user_agent USERAGENT]
                   [--proxy PROXY] [--output_location FOLDERNAME]
                   [--output_xml FILENAME] [--output_json FILENAME]
                   [--output_file FILENAME] [--output_all FILENAME]
                   [--search SEARCH] [--screenshot] [--wkhtmlloc EXELOCATION]
                   [--wkhtmlext EXT] [--wkhtmlheight HEIGHT]
                   [--wkhtmlwidth WIDTH] [--wkhtmlquality QUALITY]
                   ipaddresses

Simple program for searching for http/s pages in a range of IP addresses. if
it finds one it grabs an image of the rendered page and the html of the home

optional arguments:
  -h, --help            show this help message and exit

required:
  required arguments

  ipaddresses           Comma seperated list of IP/CIDR addresses

connection:
  Connection arguments

  --ports PORTS, -p PORTS
                        list of ports to scan for http pages. Comma seperated
                        can use - to denote range
  --user_agent USERAGENT, -u USERAGENT
                        Insert your own user agent header string
  --proxy PROXY         Proxy connection data

output:
  output parameters

  --output_location FOLDERNAME, -oL FOLDERNAME
                        folder to store all output in
  --output_xml FILENAME, -oX FILENAME
                        Output to XML file
  --output_json FILENAME, -oJ FILENAME
                        Output to json file
  --output_file FILENAME, -oF FILENAME
                        Output standard output to file
  --output_all FILENAME, -oA FILENAME
                        Output to all file types

search:
  help search for data in output

  --search SEARCH, -s SEARCH
                        a string to search for in the html

image:
  image output handling

  --screenshot          take screenshots of the webpages using wkhtmltoimage
  --wkhtmlloc EXELOCATION
                        the executable location of the wkhtmltoimage
  --wkhtmlext EXT       the extension of the image to create .png default
  --wkhtmlheight HEIGHT
                        the height of the image in real units
  --wkhtmlwidth WIDTH   the width of the image in real units
  --wkhtmlquality QUALITY
                        the quality of the image between 0 and 100 default is
                        94
```
